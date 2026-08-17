const encrypt = require('./crypto')
const request = require('axios')
const queryString = require('querystring')
const PacProxyAgent = require('pac-proxy-agent')
const http = require('http')
const https = require('https')
const fs = require('fs')
const path = require('path')
const os = require('os')
const chooseUserAgent = require('./chooseUserAgent')

// 安全读取 anonymous_token，防止 Vercel 抛出 ENOENT 崩溃
let anonymous_token = ''
try {
  const tokenPath = path.resolve(os.tmpdir(), 'anonymous_token')
  if (fs.existsSync(tokenPath)) {
    anonymous_token = fs.readFileSync(tokenPath, 'utf-8')
  }
} catch (err) {
  anonymous_token = ''
}

// 资源别名映射
const resourceTypeMap = {
  0: 'R_SO_4_',
  1: 'R_MV_5_',
  2: 'A_PR_11_',
  3: 'R_RM_50_',
  4: 'A_DJ_1_',
  5: 'R_VI_62_',
  6: 'A_EV_2_',
  7: 'A_DR_14_',
}

const createRequest = (method, url, data = {}, options = {}) => {
  return new Promise((resolve, reject) => {
    let headers = { 'User-Agent': chooseUserAgent(options.ua) }
    if (method.toUpperCase() === 'POST') {
      headers['Content-Type'] = 'application/x-www-form-urlencoded'
    }
    if (url.includes('music.163.com')) {
      headers['Referer'] = 'https://music.163.com'
    }
    if (options.realIP) {
      headers['X-Real-IP'] = options.realIP
    }

    let cookie = options.cookie || {}
    if (typeof cookie === 'string') {
      try {
        cookie = require('./index').cookieToJson(cookie)
      } catch (e) {
        cookie = {}
      }
    }
    if (anonymous_token && !cookie.MUSIC_A) {
      cookie.MUSIC_A = anonymous_token
    }

    const headerCookie = Object.keys(cookie)
      .map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(cookie[key])}`)
      .join('; ')
    if (headerCookie) {
      headers['Cookie'] = headerCookie
    }

    let ip = options.ip || options.realIP || '116.25.146.177'
    if (ip) {
      headers['X-Real-IP'] = ip
      headers['X-Forwarded-For'] = ip
    }

    let body = data
    if (options.crypto === 'weapi') {
      let csrfToken = (headers['Cookie'] || '').match(/_csrf=([^(;|$)]+)/)
      data.csrf_token = csrfToken ? csrfToken[1] : ''
      body = encrypt.weapi(data)
      url = url.replace(/\w+/, 'weapi')
    } else if (options.crypto === 'linuxapi') {
      body = encrypt.linuxapi({
        method: method,
        url: url.replace(/\w+/, 'api'),
        params: data,
      })
      headers['User-Agent'] =
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36'
      url = 'https://music.163.com/api/linux/forward'
    } else if (options.crypto === 'eapi') {
      const cookieObj = cookie || {}
      const csrfToken = cookieObj['__csrf'] || ''
      const header = {
        osver: cookieObj['osver'] || '',
        deviceId: cookieObj['deviceId'] || '',
        appver: cookieObj['appver'] || '8.7.01',
        versioncode: cookieObj['versioncode'] || '140',
        mobilename: cookieObj['mobilename'] || '',
        buildver: cookieObj['buildver'] || Date.now().toString().substr(0, 10),
        resolution: cookieObj['resolution'] || '1920x1080',
        __csrf: csrfToken,
        os: cookieObj['os'] || 'android',
        channel: cookieObj['channel'] || '',
        requestId: `${Date.now()}_${Math.floor(Math.random() * 1000).toString().padStart(4, '0')}`,
      }
      if (cookieObj['MUSIC_U']) header['MUSIC_U'] = cookieObj['MUSIC_U']
      if (cookieObj['MUSIC_A']) header['MUSIC_A'] = cookieObj['MUSIC_A']
      headers['Cookie'] = Object.keys(header)
        .map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(header[key])}`)
        .join('; ')
      data.header = header
      body = encrypt.eapi(options.url, data)
      url = url.replace(/\w+/, 'eapi')
    }

    const settings = {
      method: method,
      url: url,
      headers: headers,
      data: queryString.stringify(body),
      httpAgent: new http.Agent({ keepAlive: true }),
      httpsAgent: new https.Agent({ keepAlive: true }),
    }

    if (options.proxy) {
      if (options.proxy.indexOf('pac') > -1) {
        settings.httpAgent = new PacProxyAgent(options.proxy)
        settings.httpsAgent = new PacProxyAgent(options.proxy)
      } else {
        const purl = new URL(options.proxy)
        settings.proxy = {
          host: purl.hostname,
          port: purl.port,
        }
      }
    }

    request(settings)
      .then((res) => {
        let body = res.data
        if (typeof body === 'string') {
          try {
            body = JSON.parse(body)
          } catch (e) {}
        }
        const cookie = res.headers['set-cookie']
        if (Array.isArray(cookie)) {
          cookie.forEach((item) => {
            if (item.includes('MUSIC_A=')) {
              try {
                const token = item.match(/MUSIC_A=([^(;|$)]+)/)[1]
                fs.writeFileSync(path.resolve(os.tmpdir(), 'anonymous_token'), token)
              } catch (e) {}
            }
          })
        }
        resolve({
          status: res.status,
          body: body,
          cookie: cookie,
        })
      })
      .catch((err) => {
        reject(err.response || err)
      })
  })
}

module.exports = createRequest