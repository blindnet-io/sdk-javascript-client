// node does not support atob and btoa
global.atob = b64Encoded => Buffer.from(b64Encoded, 'base64').toString('binary')
global.btoa = str => Buffer.from(str, 'binary').toString('base64')

global.crypto = require('crypto').webcrypto

const { File } = require('web-file-polyfill')
global.File = File