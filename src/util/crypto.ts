import * as ed from 'noble-ed25519'
import { str2bin, b64str2bin, concat } from './index'

export async function deriveIv(iv: Uint8Array, i: number) {
  const hash = await crypto.subtle.digest('SHA-256', concat(iv, Uint8Array.from([i])))
  return new Uint8Array(hash).slice(0, 12)
}

export async function deriveAESKey(password: string, salt: ArrayBuffer | string, extractable: boolean = false): Promise<CryptoKey> {
  const s = typeof salt === 'string' ? b64str2bin(salt) : salt

  const passKey = await crypto.subtle.importKey(
    "raw",
    str2bin(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  )

  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: s,
      iterations: 100000,
      hash: "SHA-256",
    },
    passKey,
    { name: "AES-GCM", length: 256 },
    extractable,
    ["decrypt", "encrypt", "wrapKey", "unwrapKey"]
  )

  return aesKey
}

// TODO: handle salting
export async function deriveSecrets(
  seed: string,
  salt: Uint8Array = new Uint8Array([241, 211, 153, 239, 17, 34, 5, 112, 167, 218, 57, 131, 99, 29, 243, 84])
): Promise<{ secret1: ArrayBuffer, secret2: ArrayBuffer }> {

  const s = (seed.length === 0 || seed == undefined) ? 'seed' : seed

  const passKey = await crypto.subtle.importKey(
    "raw",
    str2bin(s),
    "PBKDF2",
    false,
    ["deriveBits"]
  )

  const derivedBits = await crypto.subtle.deriveBits(
    {
      "name": "PBKDF2",
      salt: salt,
      "iterations": 64206,
      "hash": "SHA-256"
    },
    passKey,
    512
  )

  return { secret1: new Uint8Array(derivedBits, 0, 32), secret2: new Uint8Array(derivedBits, 32, 32) }
}

export async function generateRandomAESKey(): Promise<CryptoKey> {
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  )

  return key
}

export async function generateRandomRSAKeyPair(): Promise<CryptoKeyPair> {

  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
  )

  return keyPair
}

export async function generateRandomSigningKeyPair(): Promise<{ privateKey: Uint8Array, publicKey: Uint8Array }> {
  const privateKey = ed.utils.randomPrivateKey()
  const publicKey = await ed.getPublicKey(privateKey)

  return { privateKey, publicKey }
}

export async function sign(toSign: string | ArrayBuffer, secretKey: Uint8Array): Promise<ArrayBuffer> {
  const ts = typeof toSign === 'string' ? str2bin(toSign) : toSign
  return ed.sign(new Uint8Array(ts), secretKey)
}

export function importPublicKey(publicKey: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    publicKey,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["wrapKey", "encrypt"]
  )
}

export function exportPublicKey(publicKey: CryptoKey): Promise<JsonWebKey> {
  return crypto.subtle.exportKey("jwk", publicKey)
}

export async function wrapSecretKey(secretKey: CryptoKey, aesKey: CryptoKey, iv: ArrayBuffer): Promise<ArrayBuffer> {

  const wrappedSk = await crypto.subtle.wrapKey(
    "jwk",
    secretKey,
    aesKey,
    { name: "AES-GCM", iv }
  )

  return wrappedSk
}

export async function unwrapSecretKey(wrappedSk: ArrayBuffer | string, aesKey: CryptoKey, iv: ArrayBuffer): Promise<CryptoKey> {
  const wsk = typeof wrappedSk === 'string' ? b64str2bin(wrappedSk) : wrappedSk

  return crypto.subtle.unwrapKey(
    "jwk",
    wsk,
    aesKey,
    { name: "AES-GCM", iv: iv },
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["decrypt", "unwrapKey"]
  )
}

export function wrapAESKey(aesKey: CryptoKey, wrappingKey: CryptoKey): Promise<ArrayBuffer> {

  return crypto.subtle.wrapKey(
    "jwk",
    aesKey,
    wrappingKey,
    { name: "RSA-OAEP" }
  )
}

export async function unwrapAESKey(wrappedKey: ArrayBuffer | string, secretKey: CryptoKey): Promise<CryptoKey> {
  const wk = typeof wrappedKey === 'string' ? b64str2bin(wrappedKey) : wrappedKey

  const key = await crypto.subtle.unwrapKey(
    "jwk",
    wk,
    secretKey,
    { name: "RSA-OAEP" },
    { name: "AES-GCM", length: 256 },
    true,
    ['encrypt', 'decrypt']
  )

  return key
}

export async function encryptData(aesKey: CryptoKey, iv: ArrayBuffer, data: ArrayBuffer): Promise<ArrayBuffer> {
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    aesKey,
    data
  )

  return encrypted
}

export async function decryptData(aesKey: CryptoKey, iv: ArrayBuffer, encrypted: ArrayBuffer): Promise<ArrayBuffer> {

  const decrypted = crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    aesKey,
    encrypted
  )

  return decrypted
}