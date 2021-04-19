import { KeyStore, IndexedDbKeyStore } from './keyStore'
import { BlindnetService, BlindnetServiceHttp } from './blindnetService'
import {
  str2ab,
  b642arr,
  arr2b64,
  concat,
  rethrowPromise
} from './helper'
import {
  generateIdentity,
  deriveAESKey,
  generateRandomAESKey,
  encryptSecretKey
} from './cryptoHelpers'

type Data = Uint8Array | ArrayBuffer

class BlindnetSdk {
  private service: BlindnetService = undefined
  private keyStore: KeyStore = undefined

  private constructor(jwt: string) {
    this.service = new BlindnetServiceHttp(jwt)
    this.keyStore = new IndexedDbKeyStore()
  }

  static init(jwt: string) {
    return new BlindnetSdk(jwt)
  }

  refreshJwt(jwt: string) {
    this.service = new BlindnetServiceHttp(jwt)
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
      case 'UserNotFound': {
        const { keyPair, aesKey, exportedPK, encryptedSK, salt } = await generateIdentity(passphrase)
        // TODO: handle response, errors
        const resp = await this.service.initializeUser(exportedPK, encryptedSK, salt)
        await this.keyStore.storeKeys(keyPair.privateKey, keyPair.publicKey, aesKey)
        return undefined
      }
      case 'UserFound': {
        const { PK: PKspki, eSK, salt } = getUserResp.userData

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
          new Error('Wrong passphrase provided')
        )

        await this.keyStore.storeKeys(SK, PK, aesKey)
        return undefined
      }
      case 'Error': {
        throw new Error('Fetching user data failed')
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
            throw new Error('Could not upload the encrypted public keys')
          }
        }
      }
      case 'Failed': {
        throw new Error('Fetching public keys failed')
      }
    }
  }

  async decrypt(dataId: string, encryptedData: Data, encryptedMetadata?: Data): Promise<{ data: ArrayBuffer, metadata: ArrayBuffer }> {
    const eDataKeyResp = await this.service.getDataKey(dataId)

    switch (eDataKeyResp.type) {
      case 'Success': {
        const eDataKey = eDataKeyResp.data.key
        const SK = await rethrowPromise(
          () => this.keyStore.getKey('private'),
          new Error('Private key not found. Reinitialize the current user.')
        )

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
          new Error(`Encrypted data key for data id ${dataId} could not be decrypted`)
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
          new Error(`Encrypted data with id ${dataId} could not be decrypted`)
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
          new Error(`Encrypted metadata with id ${dataId} could not be decrypted`)
        )

        return { data: data, metadata: metadata }
      }
      case 'Failed': {
        throw new Error(`Fetching data key failed for data id ${dataId}`)
      }
    }
  }

  async updatePassphrase(newPassphrase: string): Promise<void> {
    const SK = await rethrowPromise(
      () => this.keyStore.getKey('private'),
      new Error('Private key not found. Reinitialize the current user.')
    )
    const curPassKey = await rethrowPromise(
      () => this.keyStore.getKey('derived'),
      new Error('Passphrase derived key not found. Reinitialize the current user.')
    )

    const salt = window.crypto.getRandomValues(new Uint8Array(16))
    const newPassKey = await deriveAESKey(newPassphrase, salt)
    // used just once
    const iv = new Uint8Array(12)
    const encryptedSK = await encryptSecretKey(SK, newPassKey, iv)

    const updateUserResp = await this.service.updateUser(encryptedSK, salt)

    switch (updateUserResp.type) {
      case 'Success': {
        await this.keyStore.storeKey('derived', newPassKey)
        return undefined
      }
      case 'Failed': {
        throw new Error('Could not upload the new keys')
      }
    }
  }

  async giveAccess(userId: string): Promise<void> {
    const userPKResp = await this.service.getUsersPublicKey(userId)

    switch (userPKResp.type) {
      case 'Success': {
        const encryptedDataKeysResp = await this.service.getDataKeys()

        switch (encryptedDataKeysResp.type) {
          case 'Success': {
            const encryptedDataKeys = encryptedDataKeysResp.data
            const SK = await rethrowPromise(
              () => this.keyStore.getKey('private'),
              new Error('Private key not found. Reinitialize the current user.')
            )
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
                  new Error(`Could not decrypt a data key for data id ${edk.data_id}`)
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
                throw new Error(`Could not upload the encrypted data keys for a user ${userId}`)
              }
            }
          }
          case 'Failed': {
            throw new Error(`Fetching the encrypted data keys of a user ${userId} failed`)
          }
        }
      }
      case 'Failed': {
        throw new Error(`Fetching the public key of a user ${userId} failed`)
      }
    }
  }
}

export {
  BlindnetSdk
}

import { asd } from './test'
asd(1)