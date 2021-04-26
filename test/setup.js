// node does not support atob and btoa
global.atob = b64Encoded => Buffer.from(b64Encoded, 'base64').toString('binary')
global.btoa = str => Buffer.from(str, 'binary').toString('base64')

const crypto = require('crypto')
global.window = { crypto: crypto.webcrypto }