const { serveNcmApi } = require('./server')

let appPromise = null

module.exports = async (req, res) => {
  if (!appPromise) {
    appPromise = serveNcmApi({})
  }
  const app = await appPromise
  return app(req, res)
}