global.crypto = require('crypto').webcrypto

const { File } = require('web-file-polyfill')
global.File = File

const fetch = require('node-fetch')

if (!globalThis.fetch) {
  globalThis.fetch = fetch
  globalThis.Headers = fetch.Headers
  globalThis.Request = fetch.Request
  globalThis.Response = fetch.Response
}