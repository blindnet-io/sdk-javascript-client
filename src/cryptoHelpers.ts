import { str2ab } from './helper'

async function deriveAESKey(password: string, salt: Uint8Array, exportable: boolean = false): Promise<CryptoKey> {

  const passKey = await window.crypto.subtle.importKey(
    "raw",
    str2ab(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  )

  const aesKey = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    passKey,
    { name: "AES-GCM", length: 256 },
    exportable,
    ["decrypt", "encrypt", "wrapKey", "unwrapKey"]
  )

  return aesKey
}

async function generateRandomAESKey(exportable: boolean = false): Promise<CryptoKey> {
  const key = await window.crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    exportable,
    ["encrypt", "decrypt"]
  )

  return key
}

async function generateRandomRSAKeyPair(exportable: boolean = false): Promise<CryptoKeyPair> {

  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    exportable,
    ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
  )

  return keyPair
}

async function wrapSecretKey(SK: CryptoKey, aesKey: CryptoKey, iv: Uint8Array): Promise<ArrayBuffer> {

  const wrappedSk = await window.crypto.subtle.wrapKey(
    "jwk",
    SK,
    aesKey,
    {
      name: "AES-GCM",
      iv: iv
    }
  )

  return wrappedSk
}

export {
  generateRandomRSAKeyPair,
  wrapSecretKey,
  generateRandomAESKey,
  deriveAESKey
}
