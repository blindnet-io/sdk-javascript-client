import { KeyStore, IndexedDbKeyStore } from './keyStore'
import { BlindnetService, BlindnetServiceHttp, ServiceResponse } from './blindnetService'
import * as error from './error'
import * as util from './util'
import * as c from './crypto'

type JsonPrim = string | number | boolean | Array<JsonPrim> | { [key: string]: JsonPrim }
type JsonObj = { [key: string]: JsonPrim }

type Data = string | JsonObj | File | ArrayBuffer
type Metadata = JsonObj

type DataType =
  | { type: 'String' }
  | { type: 'Json' }
  | { type: 'File', name: string }
  | { type: 'Binary' }

type DecryptionResult =
  | { data: string, metadata: JsonObj, dataType: { type: 'String' } }
  | { data: JsonObj, metadata: JsonObj, dataType: { type: 'Json' } }
  | { data: File, metadata: JsonObj, dataType: { type: 'File', name: string } }
  | { data: ArrayBuffer, metadata: JsonObj, dataType: { type: 'Binary' } }

function validateServiceResponse<T>(
  resp: ServiceResponse<T>,
  errorMsg: string,
  isValid: (_: T) => boolean = _ => true
): T {
  if (resp.type === 'AuthenticationNeeded')
    throw new error.AuthenticationError()
  else if (resp.type === 'Failed')
    throw new error.BlindnetServiceError(errorMsg)
  else if (!isValid(resp.data))
    throw new error.BlindnetServiceError("Data returned from server not valid")
  else
    return resp.data
}

class CaptureBuilder {
  private data: Data
  private metadata: Metadata
  private userIds: string[]
  private groupId: string

  service: BlindnetService

  constructor(data: Data, service: BlindnetService) {
    this.data = data
    this.service = service
  }

  withMetadata(metadata: JsonObj) {
    this.metadata = metadata
    return this
  }

  forUser(userId: string) {
    this.userIds = [userId]
    return this
  }

  forUsers(userIds: string[]) {
    this.userIds = userIds
    return this
  }

  forGroup(groupId: string) {
    this.groupId = groupId
    return this
  }

  async encrypt(): Promise<{ dataId: string, encryptedData: ArrayBuffer }> {

    // types lost when compiled to javascript
    let data: Data, metadata: JsonObj
    try {
      data = this.data
      if (this.metadata == undefined)
        metadata = {}
      else
        metadata = this.metadata

    } catch {
      throw new error.BadFormatError('Data in bad format. Expected an object { data, metadata }')
    }

    if (data === null || data === undefined)
      throw new error.BadFormatError('Data can\'t be undefined or null')
    if (typeof metadata !== 'object')
      throw new error.BadFormatError('Metadata has to be an object')

    let dataBin: ArrayBuffer, dataType: DataType

    if (typeof data === 'string') {
      dataBin = util.str2bin(data)
      dataType = { type: 'String' }

    } else if (data instanceof File) {
      dataBin = await data.arrayBuffer()
      // file name is lost se it has to be stored explicitly
      dataType = { type: 'File', name: data.name }

    } else if (data instanceof ArrayBuffer || data instanceof Uint8Array) {
      dataBin = data
      dataType = { type: 'Binary' }

    } else if (typeof data === 'object') {
      dataBin = util.mapError(
        () => util.str2bin(JSON.stringify(data)),
        new error.BadFormatError('Data in bad format')
      )
      dataType = { type: 'Json' }

    } else
      throw new error.BadFormatError('Encryption of provided data format is not supported')

    const dataTypeBin = util.str2bin(JSON.stringify(dataType))
    const dataTypeLenBytes = util.to2Bytes(dataTypeBin.byteLength)
    const metadataBin = util.str2bin(JSON.stringify(metadata))
    const metadataLenBytes = util.to4Bytes(metadataBin.byteLength)

    let resp: ServiceResponse<{ publicEncryptionKey: string, userID: string }[]>
    if (this.userIds != null && Object.prototype.toString.call(this.userIds) === '[object Array]')
      resp = await this.service.getPublicKeys(this.userIds)
    else if (this.groupId != null && typeof this.groupId === 'string')
      resp = await this.service.getGroupPublicKeys(this.groupId)
    else
      throw new error.NotEncryptabeError('You must specify a list of users or a group to encrypt the data for')

    const users = validateServiceResponse(resp, 'Fetching public keys failed')

    if (users.length == 0)
      throw new error.NotEncryptabeError('Selected users not found')

    const toEncrypt = util.concat(
      new Uint8Array(dataTypeLenBytes),
      new Uint8Array(metadataLenBytes),
      dataTypeBin,
      metadataBin,
      dataBin
    )

    const dataKey = await util.mapErrorAsync(
      () => c.generateRandomAESKey(),
      new error.EncryptionError("Could not generate key")
    )
    const iv = crypto.getRandomValues(new Uint8Array(12))

    const encrypted = await util.mapErrorAsync(
      () => c.encryptData(dataKey, iv, toEncrypt),
      new error.EncryptionError("Could not encrypt data")
    )

    const encryptedUserKeys = await Promise.all(
      users.map(async user => {

        const PK = await util.mapErrorAsync(
          () => c.importPublicKey(JSON.parse(util.bin2str(util.b64str2bin(user.publicEncryptionKey)))),
          new error.EncryptionError("Public key in wrong format")
        )

        const encryptedDataKey = await util.mapErrorAsync(
          () => c.wrapAESKey(dataKey, PK),
          new error.EncryptionError("Could not encrypt data key")
        )

        return { userID: user.userID, encryptedSymmetricKey: util.bin2b64str(encryptedDataKey) }
      }))

    const postKeysResp = await this.service.postEncryptedKeys(encryptedUserKeys)
    const dataId = validateServiceResponse(postKeysResp, 'Could not upload the encrypted public keys')

    // string representation of dataId has 36 bytes (characters): 16 bytes x 2 for hex encoding and 4 hyphens
    const encryptedData = util.concat(util.str2bin(dataId), iv.buffer, encrypted)

    return { dataId, encryptedData }
  }
}

class Blindnet {
  private service: BlindnetService
  private keyStore: KeyStore
  private static protocolVersion: string = "1"

  static apiUrl = 'https://api.blindnet.io'
  static testUrl = 'https://test.blindnet.io'

  static async testBrowser() {
    try {
      const aesKey = c.generateRandomAESKey()
      if (!(aesKey instanceof Promise)) return false
      const rsaKeyPair = await c.generateRandomRSAKeyPair()
      const eccKeyPair = await c.generateRandomSigningKeyPair()

      const keyStore = new IndexedDbKeyStore()
      await keyStore.storeKey('test_key', aesKey)
      await keyStore.storeKeys(rsaKeyPair.privateKey, rsaKeyPair.publicKey, eccKeyPair.privateKey, eccKeyPair.publicKey, aesKey)
      const key = await keyStore.getKey('test_key')
      if (!(key instanceof CryptoKey)) return false
      const keys = await keyStore.getKeys()
      if (
        !(keys.eSK instanceof CryptoKey) ||
        !(keys.ePK instanceof CryptoKey) ||
        !(keys.sSK instanceof Uint8Array) ||
        !(keys.sPK instanceof Uint8Array) ||
        !(keys.aes instanceof CryptoKey)
      ) return false
      await keyStore.clear()
    } catch (e) {
      console.log(e)
      return false
    }

    return true
  }

  private constructor(service: BlindnetService, keyStore: KeyStore) {
    this.service = service
    this.keyStore = keyStore
  }

  static initCustomKeyStore(token: string, keyStore: KeyStore, apiUrl: string = Blindnet.apiUrl) {
    const service = new BlindnetServiceHttp(token, apiUrl, Blindnet.protocolVersion)
    return new Blindnet(service, keyStore)
  }

  static init(token: string, apiUrl: string = Blindnet.apiUrl) {
    const service = new BlindnetServiceHttp(token, apiUrl, Blindnet.protocolVersion)
    const keyStore = new IndexedDbKeyStore()
    return new Blindnet(service, keyStore)
  }

  static async disconnect() {
    await (new IndexedDbKeyStore()).clear()
  }

  async disconnect() {
    this.service.clearToken()
    await this.keyStore.clear()
  }

  refreshToken(token: string) {
    this.service.updateToken(token)
  }

  static async deriveSecrets(seed: string): Promise<{ blindnetSecret: string, appSecret: string }> {
    const { secret1, secret2 } = await c.deriveSecrets(seed)

    const blindnetSecret = util.bin2b64str(secret1)
    const appSecret = util.bin2b64str(secret2)

    return { blindnetSecret, appSecret }
  }

  private async getKeys() {
    const keys = await util.mapErrorAsync(
      () => this.keyStore.getKeys(),
      new error.UserNotInitializedError('Keys not initialized')
    )
    if (Object.values(keys).length === 0 || Object.values(keys).some(x => x == undefined))
      throw new error.UserNotInitializedError('Keys not initialized')

    return keys
  }

  async connect(secret: string): Promise<void> {
    await this.keyStore.clear()

    const resp = await this.service.getUserData()
    const getUserResp = validateServiceResponse(resp, 'Fetching user data failed')

    switch (getUserResp.type) {
      case 'UserNotFound': {
        const { privateKey: eSK, publicKey: ePK } = await c.generateRandomRSAKeyPair()
        const { privateKey: sSK, publicKey: sPK } = await c.generateRandomSigningKeyPair()

        const encPKexp = util.str2bin(JSON.stringify(await c.exportPublicKey(ePK)))

        const signedToken = await c.sign(this.service.token, sSK)
        const signedEncPK = await c.sign(encPKexp, sSK)

        const salt = crypto.getRandomValues(new Uint8Array(16))
        const aesKey = await c.deriveAESKey(secret, salt)

        const enc_eSK = await c.wrapSecretKey(eSK, aesKey, new Uint8Array(12))
        const enc_sSK = await c.encryptData(aesKey, new Uint8Array(12).map(_ => 1), util.concat(sSK, sPK))

        const resp = await this.service.registerUser(encPKexp, sPK, enc_eSK, enc_sSK, salt, signedToken, signedEncPK)
        validateServiceResponse(resp, 'User could not be registered')

        await this.keyStore.storeKeys(eSK, ePK, sSK, sPK, aesKey)

        return undefined
      }
      case 'UserFound': {
        const { enc_PK, e_enc_SK, sign_PK, e_sign_SK, salt } = getUserResp.userData

        const ePK = await c.importPublicKey(JSON.parse(util.bin2str(util.b64str2bin(enc_PK))))
        const aesKey = await c.deriveAESKey(secret, salt)

        const eSK = await util.mapErrorAsync(
          () => c.unwrapSecretKey(e_enc_SK, aesKey, new Uint8Array(12)),
          new error.SecretError()
        )
        const sSK = await util.mapErrorAsync(
          () => c.decryptData(aesKey, new Uint8Array(12).map(_ => 1), util.b64str2bin(e_sign_SK)),
          new error.SecretError()
        )

        await this.keyStore.storeKeys(eSK, ePK, new Uint8Array(sSK).slice(0, 32), util.b64str2bin(sign_PK), aesKey)

        return undefined
      }
    }
  }

  capture(data: Data): CaptureBuilder {
    return new CaptureBuilder(data, this.service)
  }

  async decrypt(encryptedData: ArrayBuffer): Promise<DecryptionResult> {

    const { eSK } = await this.getKeys()

    const dataId = util.mapError(
      () => util.bin2str(encryptedData.slice(0, 36)),
      new error.BadFormatError("Bad data provided")
    )
    if (dataId.length !== 36) throw new error.BadFormatError("Bad data provided")

    const resp = await this.service.getDataKey(dataId)
    const encryptedDataKey = validateServiceResponse(resp, `Fetching data key failed for data with id ${dataId}`)

    const dataKey = await util.mapErrorAsync(
      () => c.unwrapAESKey(util.b64str2bin(encryptedDataKey), eSK),
      new error.EncryptionError(`Encrypted data key for data with id ${dataId} could not be decrypted`)
    )

    const decrypted = await util.mapErrorAsync(
      () => c.decryptData(dataKey, encryptedData.slice(36, 48), encryptedData.slice(48)),
      new error.EncryptionError(`Encrypted data with id ${dataId} could not be decrypted`)
    )

    let dataBytes: ArrayBuffer, metadata: Metadata, dataType: DataType
    try {
      // decode lenght of data type
      const dataTypeLen = util.from2Bytes(Array.from(new Uint8Array(decrypted.slice(0, 2))))
      // parse data type
      const dataTypeBytes = decrypted.slice(6, 6 + dataTypeLen)
      dataType = JSON.parse(util.bin2str(dataTypeBytes))

      // decode length of metadata
      const metadataLen = util.from4Bytes(Array.from(new Uint8Array(decrypted.slice(2, 6))))
      // parse metadata
      const metadataBytes = decrypted.slice(6 + dataTypeLen, 6 + dataTypeLen + metadataLen)
      metadata = JSON.parse(util.bin2str(metadataBytes))

      dataBytes = decrypted.slice(6 + dataTypeLen + metadataLen)
    } catch {
      throw new error.BadFormatError("Bad data provided")
    }

    switch (dataType.type) {
      case 'String': {
        const data = util.mapError(
          () => util.bin2str(dataBytes),
          new error.BadFormatError("Bad data provided")
        )
        return { data, metadata, dataType }
      }

      case 'File': {
        const fileName = dataType.name
        const data = util.mapError(
          () => new File([dataBytes], fileName),
          new error.BadFormatError("Bad data provided")
        )
        return { data, metadata, dataType }
      }

      case 'Binary':
        return { data: dataBytes, metadata, dataType }

      case 'Json': {
        const data = util.mapError(
          () => JSON.parse(util.bin2str(dataBytes)),
          new error.BadFormatError("Bad data provided")
        )
        return { data, metadata, dataType }
      }
    }
  }

  // TODO: merge with decrypt
  async decryptMany(encryptedData: ArrayBuffer[]): Promise<DecryptionResult[]> {

    const { eSK } = await this.getKeys()

    const dataIds = encryptedData.map(ed => {
      const dataId = util.mapError(
        () => util.bin2str(ed.slice(0, 36)),
        new error.BadFormatError(`Bad data provided`)
      )
      if (dataId.length !== 36) throw new error.BadFormatError(`Bad data provided`)
      return dataId
    })

    const resp = await this.service.getDataKeys(dataIds)
    const encryptedKeys = validateServiceResponse(
      resp,
      `Fetching data keys failed for ids ${dataIds}`,
      keys => dataIds.every(d => keys.find(k => k.documentID === d))
    )

    const res: Promise<DecryptionResult[]> = Promise.all(
      encryptedData.map((async (ed, i) => {
        const dataId = dataIds[i]

        const dataKey = await util.mapErrorAsync(
          () => c.unwrapAESKey(util.b64str2bin(encryptedKeys.find(ek => ek.documentID === dataId).encryptedSymmetricKey), eSK),
          new error.EncryptionError(`Encrypted data key for data with id ${dataId} could not be decrypted`)
        )

        const decrypted = await util.mapErrorAsync(
          () => c.decryptData(dataKey, ed.slice(36, 48), ed.slice(48)),
          new error.EncryptionError(`Encrypted data with id ${dataId} could not be decrypted`)
        )

        let dataBytes: ArrayBuffer, metadata: Metadata, dataType: DataType
        try {
          // decode lenght of data type
          const dataTypeLen = util.from2Bytes(Array.from(new Uint8Array(decrypted.slice(0, 2))))
          // parse data type
          const dataTypeBytes = decrypted.slice(6, 6 + dataTypeLen)
          dataType = JSON.parse(util.bin2str(dataTypeBytes))

          // decode length of metadata
          const metadataLen = util.from4Bytes(Array.from(new Uint8Array(decrypted.slice(2, 6))))
          // parse metadata
          const metadataBytes = decrypted.slice(6 + dataTypeLen, 6 + dataTypeLen + metadataLen)
          metadata = JSON.parse(util.bin2str(metadataBytes))

          dataBytes = decrypted.slice(6 + dataTypeLen + metadataLen)
        } catch {
          throw new error.BadFormatError(`Bad data provided for id ${dataId}`)
        }

        switch (dataType.type) {
          case 'String': {
            const data = util.mapError(
              () => util.bin2str(dataBytes),
              new error.BadFormatError("Bad data provided")
            )
            return { data, metadata, dataType }
          }

          case 'File': {
            const fileName = dataType.name
            const data = util.mapError(
              () => new File([dataBytes], fileName),
              new error.BadFormatError("Bad data provided")
            )
            return { data, metadata, dataType }
          }

          case 'Binary':
            return { data: dataBytes, metadata, dataType }

          case 'Json': {
            const data = util.mapError(
              () => JSON.parse(util.bin2str(dataBytes)),
              new error.BadFormatError("Bad data provided")
            )
            return { data, metadata, dataType }
          }
        }
      }
      ))
    )

    return res
  }

  async changeSecret(newSecret: string, oldSecret?: string): Promise<void> {

    const { eSK, sSK } = await this.getKeys()

    const new_salt = crypto.getRandomValues(new Uint8Array(16))
    const new_aesKey = await c.deriveAESKey(newSecret, new_salt)

    const enc_eSK = await c.wrapSecretKey(eSK, new_aesKey, new Uint8Array(12))
    const enc_sSK = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: new Uint8Array(12).map(_ => 1) },
      new_aesKey,
      sSK
    )

    const updateUserResp = await this.service.updateUser(enc_eSK, enc_sSK, new_salt)
    validateServiceResponse(updateUserResp, 'Could not upload the new keys')

    await this.keyStore.storeKey('derived', new_aesKey)
  }

  async giveAccess(userId: string): Promise<void> {

    const { eSK } = await this.getKeys()

    const resp1 = await this.service.getUsersPublicKey(userId)
    const user = validateServiceResponse(resp1, `Fetching the public key of a user ${userId} failed`)

    const resp2 = await this.service.getAllDataKeys()
    const encryptedDataKeys = validateServiceResponse(resp2, `Fetching the encrypted data keys failed`)

    const userPK = await util.mapErrorAsync(
      () => c.importPublicKey(JSON.parse(util.bin2str(util.b64str2bin(user.publicEncryptionKey)))),
      new error.EncryptionError('Public key in wrong format')
    )

    const updatedKeys = await Promise.all(
      encryptedDataKeys.map(async edk => {

        const dataKey = await util.mapErrorAsync(
          () => c.unwrapAESKey(edk.encryptedSymmetricKey, eSK),
          new error.EncryptionError(`Could not decrypt a data key for data id ${edk.documentID}`)
        )

        const newDataKey = await util.mapErrorAsync(
          () => c.wrapAESKey(dataKey, userPK),
          new error.EncryptionError(`Could not encrypt data key for user ${userId}`)
        )

        return { documentID: edk.documentID, encryptedSymmetricKey: util.bin2b64str(newDataKey) }
      }))

    const updateResp = await this.service.giveAccess(userId, updatedKeys)
    validateServiceResponse(updateResp, `Uploading the encrypted data keys for a user ${userId} failed`)

    return undefined
  }
}

const helper = {
  toBase64: util.bin2b64str,
  fromBase64: util.b64str2bin,
  toHex: util.bin2Hex,
  fromHex: util.hex2bin
}

export {
  Blindnet,
  helper as util,
  error
}