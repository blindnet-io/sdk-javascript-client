import { KeyStore, IndexedDbKeyStore } from './keyStore'
import { BlindnetService, BlindnetServiceHttp } from './blindnetService'
import {
  UserNotInitializedError,
  EncryptionError,
  BlindnetServiceError,
  PassphraseError,
  AuthenticationError
} from './error'
import {
  str2ab,
  b642arr,
  arr2b64,
  concat,
  rethrowPromise
} from './helper'
import {
  generateRandomRSAKeyPair,
  generateRandomECDSAKeyPair,
  deriveAESKey,
  generateRandomAESKey,
  wrapSecretKey
} from './cryptoHelpers'

type Data = Uint8Array | ArrayBuffer

class Blindnet {
  private service: BlindnetService = undefined
  private keyStore: KeyStore = undefined
  private static protocolVersion: string = "1.0"

  private constructor(service: BlindnetService, keyStore: KeyStore) {
    this.service = service
    this.keyStore = keyStore
  }

  static initTest(service: BlindnetService, keyStore: KeyStore) {
    return new Blindnet(service, keyStore)
  }

  static init(jwt: string, endpoint: string = 'https://api.blindnet.io') {
    const service = new BlindnetServiceHttp(jwt, endpoint, Blindnet.protocolVersion)
    const keyStore = new IndexedDbKeyStore()
    return new Blindnet(service, keyStore)
  }

  static clearKeys() {
    (new IndexedDbKeyStore()).clear()
  }

  refreshJwt(jwt: string) {
    this.service = new BlindnetServiceHttp(jwt, this.service.endpoint, Blindnet.protocolVersion)
  }

  static async derivePasswords(password: string): Promise<{ blindnetPassphrase: string, appPassword: string }> {
    const passKey = await window.crypto.subtle.importKey(
      "raw",
      str2ab(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    )

    // TODO: bit derivation should be salted
    // const salt = window.crypto.getRandomValues(new Uint8Array(16))
    const salt = new Uint8Array([241, 211, 153, 239, 17, 34, 5, 112, 167, 218, 57, 131, 99, 29, 243, 84])

    const derivedBits = await window.crypto.subtle.deriveBits(
      {
        "name": "PBKDF2",
        salt: salt,
        "iterations": 64206,
        "hash": "SHA-256"
      },
      passKey,
      512
    )

    const blindnetPassBits = new Uint8Array(derivedBits, 0, 32)
    const appPassBits = new Uint8Array(derivedBits, 32, 32)

    return { blindnetPassphrase: arr2b64(blindnetPassBits), appPassword: arr2b64(appPassBits) }
  }

  async initUser(passphrase: string): Promise<void> {
    await this.keyStore.clear()

    const getUserResp = await this.service.getUserData()

    switch (getUserResp.type) {
      case 'Success': {
        switch (getUserResp.data.type) {
          case 'UserNotFound': {

            const encryptionKeyPair = await generateRandomRSAKeyPair(true)
            const signKeyPair = await generateRandomECDSAKeyPair(true)

            const encryptionPK = await window.crypto.subtle.exportKey("spki", encryptionKeyPair.publicKey)
            const signPK = await window.crypto.subtle.exportKey("spki", signKeyPair.publicKey)

            const salt = window.crypto.getRandomValues(new Uint8Array(16))
            const aesKey = await deriveAESKey(passphrase, salt)
            // TODO: used just once
            const iv = new Uint8Array(12)
            const enc_encryptionSK = await wrapSecretKey(encryptionKeyPair.privateKey, aesKey, iv)

            const signedJwt = await window.crypto.subtle.sign(
              {
                name: "ECDSA",
                hash: { name: "SHA-384" },
              },
              signKeyPair.privateKey,
              str2ab(this.service.jwt)
            )

            // not used in this use-case
            const enc_signSK = new ArrayBuffer(0)

            const resp = await this.service.initializeUser(encryptionPK, signPK, enc_encryptionSK, enc_signSK, salt, signedJwt)
            await this.keyStore.storeKeys(encryptionKeyPair.privateKey, encryptionKeyPair.publicKey, aesKey)
            return undefined
          }
          case 'UserFound': {
            const { PK: PKspki, eSK, salt } = getUserResp.data.userData

            const PK = await window.crypto.subtle.importKey(
              "spki",
              b642arr(PKspki),
              { name: "RSA-OAEP", hash: "SHA-256" },
              true,
              ["encrypt"]
            )

            const aesKey = await deriveAESKey(passphrase, b642arr(salt))

            const iv = new Uint8Array(12)

            const SK = await rethrowPromise(
              () => window.crypto.subtle.unwrapKey(
                "pkcs8",
                b642arr(eSK),
                aesKey,
                { name: "AES-GCM", iv: iv },
                { name: "RSA-OAEP", hash: "SHA-256" },
                true,
                ["decrypt", "unwrapKey"]
              ),
              new PassphraseError('Wrong passphrase provided')
            )

            await this.keyStore.storeKeys(SK, PK, aesKey)
            return undefined
          }
        }
      }
      case 'AuthenticationNeeded': {
        throw new AuthenticationError('Please generate a valid JWT')
      }
      case 'Failed': {
        throw new BlindnetServiceError('Fetching user data failed')
      }
    }
  }

  async encrypt(data: Data, metadata?: Data): Promise<{ dataId: string, encryptedData: ArrayBuffer, encryptedMetadata: ArrayBuffer }> {

    const groupPKsResp = await this.service.getGroupPublicKeys()

    switch (groupPKsResp.type) {
      case 'Success': {
        const users = groupPKsResp.data

        const dataKey = await generateRandomAESKey(true)
        const iv1 = window.crypto.getRandomValues(new Uint8Array(12))

        const encryptedData = await window.crypto.subtle.encrypt(
          { name: "AES-GCM", iv: iv1 },
          dataKey,
          data
        )
        const encryptedDataWithIV = concat(iv1.buffer, encryptedData)

        let encryptedMetadataWithIV = new ArrayBuffer(0)
        if (metadata != undefined) {
          const iv2 = window.crypto.getRandomValues(new Uint8Array(12))
          const encryptedMetadata = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv2 },
            dataKey,
            metadata
          )
          encryptedMetadataWithIV = concat(iv2.buffer, encryptedMetadata)
        }

        const encryptedUserKeys = await Promise.all(
          users.map(async user => {

            const PK = await window.crypto.subtle.importKey(
              "spki",
              b642arr(user.PK),
              { name: "RSA-OAEP", hash: "SHA-256" },
              true,
              ["wrapKey"]
            )

            const encDataKey = await window.crypto.subtle.wrapKey(
              "jwk",
              dataKey,
              PK,
              { name: "RSA-OAEP" }
            )

            return { user_id: user.user_id, eKey: arr2b64(encDataKey) }
          }))

        const postKeysResp = await this.service.postEncryptedKeys(encryptedUserKeys)

        switch (postKeysResp.type) {
          case 'Success': {
            return { dataId: postKeysResp.data.data_id, encryptedData: encryptedDataWithIV, encryptedMetadata: encryptedMetadataWithIV }
          }
          case 'Failed': {
            throw new BlindnetServiceError('Could not upload the encrypted public keys')
          }
        }
      }
      case 'AuthenticationNeeded': {
        throw new AuthenticationError('Please generate a valid JWT')
      }
      case 'Failed': {
        throw new BlindnetServiceError('Fetching public keys failed')
      }
    }
  }

  async decrypt(dataId: string, encryptedData: Data, encryptedMetadata?: Data): Promise<{ data: ArrayBuffer, metadata: ArrayBuffer }> {

    const SK = await rethrowPromise(
      () => this.keyStore.getKey('private'),
      new UserNotInitializedError('Private key not found')
    )

    const eDataKeyResp = await this.service.getDataKey(dataId)

    switch (eDataKeyResp.type) {
      case 'Success': {
        const eDataKey = eDataKeyResp.data.key

        const dataKey = await rethrowPromise(
          () => window.crypto.subtle.unwrapKey(
            "jwk",
            b642arr(eDataKey),
            SK,
            { name: "RSA-OAEP" },
            { name: "AES-GCM", length: 256 },
            false,
            ['decrypt']
          ),
          new EncryptionError(`Encrypted data key for data id ${dataId} could not be decrypted`)
        )

        const data = await rethrowPromise(
          () => window.crypto.subtle.decrypt(
            {
              name: "AES-GCM",
              iv: encryptedData.slice(0, 12),
            },
            dataKey,
            encryptedData.slice(12)
          ),
          new EncryptionError(`Encrypted data with id ${dataId} could not be decrypted`)
        )

        const metadata = await rethrowPromise(
          () =>
            (encryptedMetadata != undefined)
              ?
              window.crypto.subtle.decrypt(
                {
                  name: "AES-GCM",
                  iv: encryptedMetadata.slice(0, 12),
                },
                dataKey,
                encryptedMetadata.slice(12)
              )
              :
              Promise.resolve(new ArrayBuffer(0))
          ,
          new EncryptionError(`Encrypted metadata with id ${dataId} could not be decrypted`)
        )

        return { data: data, metadata: metadata }
      }
      case 'AuthenticationNeeded': {
        throw new AuthenticationError('Please generate a valid JWT')
      }
      case 'Failed': {
        throw new BlindnetServiceError(`Fetching data key failed for data id ${dataId}`)
      }
    }
  }

  async updatePassphrase(newPassphrase: string): Promise<void> {
    const SK = await rethrowPromise(
      () => this.keyStore.getKey('private'),
      new UserNotInitializedError('Private key not found')
    )
    const curPassKey = await rethrowPromise(
      () => this.keyStore.getKey('derived'),
      new UserNotInitializedError('Passphrase derived key not found')
    )

    const salt = window.crypto.getRandomValues(new Uint8Array(16))
    const newPassKey = await deriveAESKey(newPassphrase, salt)
    // used just once
    const iv = new Uint8Array(12)
    const encryptedSK = await wrapSecretKey(SK, newPassKey, iv)

    const updateUserResp = await this.service.updateUser(encryptedSK, salt)

    switch (updateUserResp.type) {
      case 'Success': {
        await this.keyStore.storeKey('derived', newPassKey)
        return undefined
      }
      case 'AuthenticationNeeded': {
        throw new AuthenticationError('Please generate a valid JWT')
      }
      case 'Failed': {
        throw new BlindnetServiceError('Could not upload the new keys')
      }
    }
  }

  async giveAccess(userId: string): Promise<void> {

    const SK = await rethrowPromise(
      () => this.keyStore.getKey('private'),
      new UserNotInitializedError('Private key not found')
    )

    const userPKResp = await this.service.getUsersPublicKey(userId)

    switch (userPKResp.type) {
      case 'Success': {
        const encryptedDataKeysResp = await this.service.getDataKeys()

        switch (encryptedDataKeysResp.type) {
          case 'Success': {
            const encryptedDataKeys = encryptedDataKeysResp.data
            const userPKspki = userPKResp.data.PK

            const userPK = await window.crypto.subtle.importKey(
              "spki",
              b642arr(userPKspki),
              { name: "RSA-OAEP", hash: "SHA-256" },
              false,
              ["wrapKey"]
            )

            const updatedKeys = await Promise.all(
              encryptedDataKeysResp.data.map(async edk => {

                const dataKey = await rethrowPromise(
                  () => window.crypto.subtle.unwrapKey(
                    "jwk",
                    b642arr(edk.eKey),
                    SK,
                    { name: "RSA-OAEP" },
                    { name: "AES-GCM", length: 256 },
                    true,
                    ['decrypt']
                  ),
                  new EncryptionError(`Could not decrypt a data key for data id ${edk.data_id}`)
                )

                const newDataKey = await window.crypto.subtle.wrapKey(
                  "jwk",
                  dataKey,
                  userPK,
                  { name: "RSA-OAEP" }
                )

                return { data_id: edk.data_id, eKey: arr2b64(newDataKey) }
              }))

            const updateRes = await this.service.giveAccess(userId, updatedKeys)

            switch (updateRes.type) {
              case 'Success': {
                return undefined
              }
              case 'Failed': {
                throw new BlindnetServiceError(`Could not upload the encrypted data keys for a user ${userId}`)
              }
            }
          }
          case 'Failed': {
            throw new BlindnetServiceError(`Fetching the encrypted data keys of a user ${userId} failed`)
          }
        }
      }
      case 'AuthenticationNeeded': {
        throw new AuthenticationError('Please generate a valid JWT')
      }
      case 'Failed': {
        throw new BlindnetServiceError(`Fetching the public key of a user ${userId} failed`)
      }
    }
  }
}

export {
  Blindnet
}

import { asd } from './test'
asd(1)