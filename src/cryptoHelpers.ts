import { str2ab } from './helper'

async function deriveAESKey(passphrase: string, salt: Uint8Array, exportable: boolean = false): Promise<CryptoKey> {

  const passKey = await window.crypto.subtle.importKey(
    "raw",
    str2ab(passphrase),
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
    ["wrapKey", "unwrapKey"]
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

async function encryptSecretKey(SK: CryptoKey, aesKey: CryptoKey, iv: Uint8Array): Promise<ArrayBuffer> {
  const wrappedSk = await window.crypto.subtle.wrapKey(
    "pkcs8",
    SK,
    aesKey,
    {
      name: "AES-GCM",
      iv: iv
    }
  )

  return wrappedSk
}

async function generateIdentity(passphrase: string) {
  const keyPair = await generateRandomRSAKeyPair(true)

  const exportedPK = await window.crypto.subtle.exportKey("spki", keyPair.publicKey)

  const salt = window.crypto.getRandomValues(new Uint8Array(16))
  const aesKey = await deriveAESKey(passphrase, salt)
  // used just once
  const iv = new Uint8Array(12)
  const encryptedSK = await encryptSecretKey(keyPair.privateKey, aesKey, iv)

  return { keyPair, aesKey, exportedPK, encryptedSK, salt }
}

export {
  generateIdentity,
  encryptSecretKey,
  generateRandomAESKey,
  deriveAESKey
}
