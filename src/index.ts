import * as ed from 'noble-ed25519'
import { KeyStore, IndexedDbKeyStore } from './keyStore'
import { BlindnetService, BlindnetServiceHttp, ServiceResponse } from './blindnetService'
import {
  UserNotInitializedError,
  EncryptionError,
  BlindnetServiceError,
  PasswordError,
  AuthenticationError,
  NotEncryptabeError,
  NoAccessError,
  UserNotFoundError
} from './error'
import {
  str2ab,
  b642arr,
  arr2b64,
  concat,
  concat3,
  getInt64Bytes,
  intFromBytes,
  rethrowPromise
} from './helper'
import {
  generateRandomRSAKeyPair,
  deriveAESKey,
  generateRandomAESKey,
  wrapSecretKey
} from './cryptoHelpers'

type Data = Uint8Array | ArrayBuffer

function validateServiceResponse<T>(resp: ServiceResponse<T>, errorMsg: string): T {
  if (resp.type === 'AuthenticationNeeded')
    throw new AuthenticationError()
  else if (resp.type === 'Failed')
    throw new BlindnetServiceError(errorMsg)
  else
    return resp.data
}

class Blindnet {
  private service: BlindnetService = undefined
  private keyStore: KeyStore = undefined
  private static protocolVersion: string = "1"

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

  static disconnect() {
    (new IndexedDbKeyStore()).clear()
  }

  refreshToken(jwt: string) {
    this.service = new BlindnetServiceHttp(jwt, this.service.endpoint, Blindnet.protocolVersion)
  }

  static async deriveSecrets(password: string): Promise<{ blindnetPassword: string, appPassword: string }> {
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

    return { blindnetPassword: arr2b64(blindnetPassBits), appPassword: arr2b64(appPassBits) }
  }

  async connect(password: string): Promise<void> {
    await this.keyStore.clear()

    const resp = await this.service.getUserData()
    const getUserResp = validateServiceResponse(resp, 'Fetching user data failed')

    switch (getUserResp.type) {
      case 'UserNotFound': {
        const encryptionKeyPair = await generateRandomRSAKeyPair(true)
        const signSK = ed.utils.randomPrivateKey()
        const signPK = await ed.getPublicKey(signSK)

        const encryptionPK = await window.crypto.subtle.exportKey("spki", encryptionKeyPair.publicKey)

        const salt = window.crypto.getRandomValues(new Uint8Array(16))
        const aesKey = await deriveAESKey(password, salt)

        const signedJwt = await ed.sign(new Uint8Array(str2ab(this.service.jwt)), signSK)
        const signedEncPK = await ed.sign(new Uint8Array(encryptionPK), signSK)

        // TODO
        const iv = new Uint8Array(12)
        const enc_encryptionSK = await wrapSecretKey(encryptionKeyPair.privateKey, aesKey, iv)
        const enc_signSK = await window.crypto.subtle.encrypt(
          { name: "AES-GCM", iv: iv },
          aesKey,
          signSK
        )

        const resp = await this.service.registerUser(encryptionPK, signPK, enc_encryptionSK, enc_signSK, salt, signedJwt, signedEncPK)
        validateServiceResponse(resp, 'User could not be registered')

        await this.keyStore.storeKeys(encryptionKeyPair.privateKey, encryptionKeyPair.publicKey, signSK, signPK, aesKey)
        return undefined
      }
      case 'UserFound': {
        const { enc_PK, e_enc_SK, sign_PK, e_sign_SK, salt } = getUserResp.userData

        const ePK = await window.crypto.subtle.importKey(
          "spki",
          b642arr(enc_PK),
          { name: "RSA-OAEP", hash: "SHA-256" },
          true,
          ["encrypt"]
        )

        const aesKey = await deriveAESKey(password, b642arr(salt))

        const iv = new Uint8Array(12)

        const eSK = await rethrowPromise(
          () => window.crypto.subtle.unwrapKey(
            "jwk",
            b642arr(e_enc_SK),
            aesKey,
            { name: "AES-GCM", iv: iv },
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["decrypt", "unwrapKey"]
          ),
          new PasswordError()
        )
        const sSK =
          await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            aesKey,
            b642arr(e_sign_SK)
          )

        await this.keyStore.storeKeys(eSK, ePK, new Uint8Array(sSK), b642arr(sign_PK), aesKey)
        return undefined
      }
    }
  }

  async encrypt(data: Data, metadata?: any): Promise<{ dataId: string, encryptedData: ArrayBuffer }> {

    let metadataBytes

    if (metadata != undefined) {
      if (metadata instanceof ArrayBuffer || metadata instanceof Uint8Array)
        metadataBytes = metadata
      else metadataBytes = str2ab(JSON.stringify(metadata))
    } else
      metadataBytes = new ArrayBuffer(0)

    const resp = await this.service.getGroupPublicKeys()
    const users = validateServiceResponse(resp, 'Fetching public keys failed')

    if (users.length == 0)
      throw new NotEncryptabeError()

    const dataKey = await generateRandomAESKey(true)
    const iv = window.crypto.getRandomValues(new Uint8Array(12))

    const metadataLenBytes = getInt64Bytes(metadataBytes.byteLength)
    const allData = concat3(new Uint8Array(metadataLenBytes), metadataBytes, data)

    const encryptedData = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      dataKey,
      allData
    )

    const encryptedUserKeys = await Promise.all(
      users.map(async user => {

        const PK = await window.crypto.subtle.importKey(
          "spki",
          b642arr(user.publicEncryptionKey),
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

        return { userID: user.userID, encryptedSymmetricKey: arr2b64(encDataKey) }
      }))

    const postKeysResp = await this.service.postEncryptedKeys(encryptedUserKeys)
    const dataId = validateServiceResponse(postKeysResp, 'Could not upload the encrypted public keys')

    return { dataId: dataId, encryptedData: concat(iv.buffer, encryptedData) }
  }

  async decrypt(dataId: string, encryptedData: Data): Promise<{ data: ArrayBuffer, metadata: ArrayBuffer }> {

    const SK = await rethrowPromise(
      () => this.keyStore.getKey('private_enc'),
      new UserNotInitializedError('Private key not found')
    )

    const resp = await this.service.getDataKey(dataId)
    const eDataKeyResp = validateServiceResponse(resp, `Fetching data key failed for data with id ${dataId}`)

    if (eDataKeyResp.type === 'KeyNotFound')
      throw new NoAccessError(`A user has no access to data with id ${dataId}`)

    const eDataKey = eDataKeyResp.key

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
      new EncryptionError(`Encrypted data key for data with id ${dataId} could not be decrypted`)
    )

    const allData = await rethrowPromise(
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

    const metadataLen = intFromBytes(Array.from(new Uint8Array(allData.slice(0, 8))))
    const metadata = allData.slice(8, 8 + metadataLen)
    const data = allData.slice(8 + metadataLen)

    return { data: data, metadata: metadata }

  }

  // TODO: refactor repeating code
  async changePassword(newPassword: string, oldPassword?: string): Promise<void> {

    if (oldPassword == undefined) {

      const eSK = await rethrowPromise(
        () => this.keyStore.getKey('private_enc'),
        new UserNotInitializedError('Private key not found')
      )
      const sSK = await rethrowPromise(
        () => this.keyStore.getSignKey('private_sign'),
        new UserNotInitializedError('Private key not found')
      )
      const curPassKey = await rethrowPromise(
        () => this.keyStore.getKey('derived'),
        new UserNotInitializedError('Password derived key not found')
      )

      const salt = window.crypto.getRandomValues(new Uint8Array(16))
      const newPassKey = await deriveAESKey(newPassword, salt)
      // TODO:
      const iv = new Uint8Array(12)
      const encryptedESK = await wrapSecretKey(eSK, newPassKey, iv)
      const encryptedSSK = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        newPassKey,
        sSK
      )

      const resp = await this.service.updateUser(encryptedESK, encryptedSSK, salt)
      validateServiceResponse(resp, 'Could not upload the new keys')

      await this.keyStore.storeKey('derived', newPassKey)

      return undefined
    } else {

      const resp = await this.service.getUserData()
      const getUserResp = validateServiceResponse(resp, 'Fetching user data failed')

      // TODO
      if (getUserResp.type == 'UserNotFound')
        throw new UserNotFoundError('')

      const { enc_PK, e_enc_SK, sign_PK, e_sign_SK, salt } = getUserResp.userData

      const ePK = await window.crypto.subtle.importKey(
        "spki",
        b642arr(enc_PK),
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"]
      )

      const aesKey = await deriveAESKey(oldPassword, b642arr(salt))

      const iv = new Uint8Array(12)

      const eSK = await rethrowPromise(
        () => window.crypto.subtle.unwrapKey(
          "jwk",
          b642arr(e_enc_SK),
          aesKey,
          { name: "AES-GCM", iv: iv },
          { name: "RSA-OAEP", hash: "SHA-256" },
          true,
          ["decrypt", "unwrapKey"]
        ),
        new PasswordError()
      )
      const sSK =
        await window.crypto.subtle.decrypt(
          { name: "AES-GCM", iv: iv },
          aesKey,
          b642arr(e_sign_SK)
        )

      const newSalt = window.crypto.getRandomValues(new Uint8Array(16))
      const newPassKey = await deriveAESKey(newPassword, newSalt)
      // TODO:
      const newIv = new Uint8Array(12)
      const encryptedESK = await wrapSecretKey(eSK, newPassKey, newIv)
      const encryptedSSK = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: newIv },
        newPassKey,
        sSK
      )

      const updateUserResp = await this.service.updateUser(encryptedESK, encryptedSSK, newSalt)
      validateServiceResponse(updateUserResp, 'Could not upload the new keys')

      await this.keyStore.storeKey('derived', newPassKey)

      return undefined
    }
  }

  async giveAccess(userId: string): Promise<void> {

    const SK = await rethrowPromise(
      () => this.keyStore.getKey('private_enc'),
      new UserNotInitializedError('Private key not found')
    )

    const resp1 = await this.service.getUsersPublicKey(userId)
    const userPKResp = validateServiceResponse(resp1, `Fetching the public key of a user ${userId} failed`)

    if (userPKResp.type == 'UserNotFound') {
      throw new UserNotFoundError(`User ${userId} not registered.`)
    }

    const resp2 = await this.service.getDataKeys()
    const encryptedDataKeys = validateServiceResponse(resp2, `Fetching the encrypted data keys failed`)

    const userPKspki = userPKResp.publicEncryptionKey

    const userPK = await window.crypto.subtle.importKey(
      "spki",
      b642arr(userPKspki),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["wrapKey"]
    )

    const updatedKeys = await Promise.all(
      encryptedDataKeys.map(async edk => {

        const dataKey = await rethrowPromise(
          () => window.crypto.subtle.unwrapKey(
            "jwk",
            b642arr(edk.encryptedSymmetricKey),
            SK,
            { name: "RSA-OAEP" },
            { name: "AES-GCM", length: 256 },
            true,
            ['decrypt']
          ),
          new EncryptionError(`Could not decrypt a data key for data id ${edk.documentID}`)
        )

        const newDataKey = await window.crypto.subtle.wrapKey(
          "jwk",
          dataKey,
          userPK,
          { name: "RSA-OAEP" }
        )

        return { documentID: edk.documentID, encryptedSymmetricKey: arr2b64(newDataKey) }
      }))

    const updateResp = await this.service.giveAccess(userId, updatedKeys)
    validateServiceResponse(updateResp, `Uploading the encrypted data keys for a user ${userId} failed`)

    return undefined
  }
}

export default Blindnet