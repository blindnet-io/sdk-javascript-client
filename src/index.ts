import { KeyStore, IndexedDbKeyStore } from './storage/KeyStore'
import { BlindnetService, BlindnetServiceHttp, ServiceResponse } from './services/BlindnetService'
import * as error from './error'
import * as util from './util'
import * as c from './util/crypto'
import { AzureStorageService, StorageService } from './services/StorageService'

type JsonPrim = string | number | boolean | Array<JsonPrim> | { [key: string]: JsonPrim }
type JsonObj = { [key: string]: JsonPrim }

type Data = string | JsonObj | File | ArrayBuffer
type Metadata = JsonObj

type DataType =
  | { type: 'String' }
  | { type: 'Json' }
  | { type: 'File', name: string, size?: number }
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
  else if (resp.type === 'Failed' || !isValid(resp.data))
    throw new error.BlindnetServiceError(errorMsg)
  else
    return resp.data
}

class CaptureBuilder {
  private data: Data
  private metadata: Metadata
  private userIds: string[]
  private groupId: string

  service: BlindnetService
  storageService: StorageService

  constructor(data: Data, service: BlindnetService, storageService: StorageService) {
    this.data = data
    this.metadata = {}
    this.service = service
    this.storageService = storageService
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

    const { data, metadata } = this

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

  async store(): Promise<{ dataId: string }> {

    const { data, metadata } = this

    if (!(data instanceof File))
      throw new error.BadFormatError('Only files are supported')
    if (typeof metadata !== 'object')
      throw new error.BadFormatError('Metadata has to be an object')

    // generate key
    const dataKey = await util.mapErrorAsync(
      () => c.generateRandomAESKey(),
      new error.EncryptionError("Could not generate key")
    )

    // get public keys
    let getPublicKeysResp: ServiceResponse<{ publicEncryptionKey: string, userID: string }[]>
    if (this.userIds != null && Object.prototype.toString.call(this.userIds) === '[object Array]')
      getPublicKeysResp = await this.service.getPublicKeys(this.userIds)
    else if (this.groupId != null && typeof this.groupId === 'string')
      getPublicKeysResp = await this.service.getGroupPublicKeys(this.groupId)
    else
      throw new error.NotEncryptabeError('You must specify a list of users or a group to encrypt the data for')

    const users = validateServiceResponse(getPublicKeysResp, 'Fetching public keys failed')

    // get data_id from the server
    const initUploadResp = await this.service.initializeUpload()
    const { dataId } = validateServiceResponse(initUploadResp, 'Upload initialization failed')

    // encrypt data key for each user
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

    const postKeysResp = await this.service.postEncryptedKeysForData(encryptedUserKeys, dataId)
    validateServiceResponse(postKeysResp, 'Could not upload the encrypted public keys')

    const dataType = { type: 'File', name: data.name, size: data.size }
    const dataTypeBin = util.str2bin(JSON.stringify(dataType))
    const dataTypeLenBytes = util.to2Bytes(dataTypeBin.byteLength)
    const metadataBin = util.str2bin(JSON.stringify(metadata))

    const toEncrypt = util.concat(
      new Uint8Array(dataTypeLenBytes),
      dataTypeBin,
      metadataBin
    )

    const iv = crypto.getRandomValues(new Uint8Array(12))

    // encrypt metadata
    const encryptedMetadata = await util.mapErrorAsync(
      () => c.encryptData(dataKey, iv, toEncrypt),
      new error.EncryptionError("Could not encrypt data")
    )
      .then(enc => util.concat(iv.buffer, enc))

    const storeMetadataResp = await this.service.storeMetadata(dataId, util.bin2b64str(encryptedMetadata))
    validateServiceResponse(storeMetadataResp, 'Could not store metadata')

    // chunk_size
    const blockSize = 4000000

    // traverse file (offset -> 0 to file size)
    // - slice chunk -> file.slice(offset, offset + chunk_size)
    // - enc -> encrypt(chunk, key, hash([...iv, i]).slice(0, 12))
    // - upload enc
    // - store locally block_id
    async function uploadBlocks(
      i: number,
      offset: number,
      dataId: string,
      file: File,
      blockIds: string[],
      service: BlindnetService,
      storageService: StorageService
    ) {

      if (offset >= file.size) return blockIds

      const filePart = await file.slice(offset, offset + blockSize).arrayBuffer()

      const partIv = await c.deriveIv(iv, i)

      const encryptedPart: ArrayBuffer = await util.mapErrorAsync(
        () => c.encryptData(dataKey, partIv, filePart),
        new error.EncryptionError("Could not encrypt data")
      )

      const uploadBlockUrlResp = await service.getUploadBlockUrl(dataId, encryptedPart.byteLength)
      const { blockId, date, authorization, url } = validateServiceResponse(uploadBlockUrlResp, 'Could not get upload url')

      const uploadRes = await storageService.uploadBlock(url, authorization, date, encryptedPart)
      validateServiceResponse(uploadRes, 'Could not upload data part')

      return uploadBlocks(i + 1, offset + blockSize, dataId, file, [...blockIds, blockId], service, storageService)
    }

    const blockIds = await uploadBlocks(0, 0, dataId, data, [], this.service, this.storageService)

    // commit
    const finishUploadResp = await this.service.finishUpload(dataId, blockIds)
    validateServiceResponse(finishUploadResp, 'Could not get upload url')

    return { dataId }
  }
}

class Blindnet {
  private service: BlindnetService
  private storageService: StorageService
  private keyStore: KeyStore
  private static protocolVersion: string = "1"

  static apiUrl = 'https://api.blindnet.io'
  static testUrl = 'https://test.blindnet.io'

  static async testBrowser() {
    try {
      const aesKeyP = c.generateRandomAESKey()
      if (!(aesKeyP instanceof Promise)) return false
      const aesKey = await aesKeyP
      const rsaKeyPair = await c.generateRandomRSAKeyPair()
      const eccKeyPair = await c.generateRandomSigningKeyPair()

      const keyStore = new IndexedDbKeyStore('blindnet_test')
      await keyStore.clear()
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
      console.error(e)
      return false
    }

    return true
  }

  private constructor(service: BlindnetService, storageService: StorageService, keyStore: KeyStore) {
    this.service = service
    this.storageService = storageService
    this.keyStore = keyStore
  }

  static initCustomKeyStore(token: string, keyStore: KeyStore, apiUrl: string = Blindnet.apiUrl) {
    const service = new BlindnetServiceHttp(token, apiUrl, Blindnet.protocolVersion)
    const storageService = new AzureStorageService()
    return new Blindnet(service, storageService, keyStore)
  }

  static init(token: string, apiUrl: string = Blindnet.apiUrl) {
    const service = new BlindnetServiceHttp(token, apiUrl, Blindnet.protocolVersion)
    const storageService = new AzureStorageService()
    const keyStore = new IndexedDbKeyStore()
    return new Blindnet(service, storageService, keyStore)
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
    return new CaptureBuilder(data, this.service, this.storageService)
  }

  async retrieve(dataId: string): Promise<{ data: ReadableStream, metadata: Metadata, dataType: DataType }> {

    const { eSK } = await this.getKeys()

    // get data key
    const encryptedDataKeyresp = await this.service.getDataKey(dataId)
    const encryptedDataKey = validateServiceResponse(encryptedDataKeyresp, `Fetching data key failed for data with id ${dataId}`)

    const dataKey = await util.mapErrorAsync(
      () => c.unwrapAESKey(util.b64str2bin(encryptedDataKey), eSK),
      new error.EncryptionError(`Encrypted data key for data with id ${dataId} could not be decrypted`)
    )

    // get metadata
    const encryptedMetadataResp = await this.service.getMetadata(dataId)
    const encryptedMetadataB64 = validateServiceResponse(encryptedMetadataResp, `Fetching metadata failed for id ${dataId}`)
    const encMetaBin = util.b64str2bin(encryptedMetadataB64)

    const iv = encMetaBin.slice(0, 12)
    const decrypted = await util.mapErrorAsync(
      () => c.decryptData(dataKey, iv, encMetaBin.slice(12)),
      new error.EncryptionError(`Encrypted data with id ${dataId} could not be decrypted`)
    )

    let metadata: Metadata, dataType: DataType
    try {
      // decode lenght of data type
      const dataTypeLen = util.from2Bytes(Array.from(new Uint8Array(decrypted.slice(0, 2))))
      // parse data type
      const dataTypeBytes = decrypted.slice(2, 2 + dataTypeLen)
      dataType = JSON.parse(util.bin2str(dataTypeBytes))

      // parse metadata
      const metadataBytes = decrypted.slice(2 + dataTypeLen)
      metadata = JSON.parse(util.bin2str(metadataBytes))
    } catch {
      throw new error.BadFormatError("Bad data provided")
    }

    // get download link
    const getDownloadLinkResp = await this.service.getDownloadLink(dataId)
    const { date, authorization, url } = validateServiceResponse(getDownloadLinkResp, 'Could not get download link')

    // download from storage
    const getBlobResp = await this.storageService.downloadBlob(url, authorization, date)
    const encrytedFileStream = validateServiceResponse(getBlobResp, 'Could not download file')

    const blockSize = 4000000 + 16

    const encryptedFileStreamReader = encrytedFileStream.getReader()

    const chunkedStream = new ReadableStream({
      start(ctrl) {
        let leftOverBytes = new Uint8Array()

        function pump() {

          encryptedFileStreamReader.read().then(readRes => {
            const { done, value: chunk } = readRes
            if (done) {
              if (leftOverBytes.length > 0) {
                ctrl.enqueue(leftOverBytes.slice(0, leftOverBytes.length))
              }
              ctrl.close();
              return undefined;
            }

            if (leftOverBytes.length + chunk.length === blockSize) {

              var newChunk = new Uint8Array(blockSize)
              newChunk.set(leftOverBytes, 0)
              newChunk.set(chunk, leftOverBytes.length)
              ctrl.enqueue(newChunk)
              leftOverBytes = new Uint8Array()

            } else if (leftOverBytes.length + chunk.length < blockSize) {

              var newChunk = new Uint8Array(leftOverBytes.length + chunk.length)
              newChunk.set(leftOverBytes, 0)
              newChunk.set(chunk, leftOverBytes.length)
              leftOverBytes = new Uint8Array(newChunk)

            } else if (leftOverBytes.length + chunk.length > blockSize) {

              var newChunk = new Uint8Array(blockSize)
              newChunk.set(leftOverBytes, 0)
              newChunk.set(chunk.slice(0, blockSize - leftOverBytes.length), leftOverBytes.length)
              ctrl.enqueue(newChunk)

              const slicedChunk = chunk.slice(blockSize - leftOverBytes.length)

              function p(v: Uint8Array) {
                if (v.length < blockSize)
                  leftOverBytes = new Uint8Array(v)
                else {
                  const chunk = v.slice(0, blockSize)
                  ctrl.enqueue(chunk)
                  p(v.slice(blockSize))
                }
              }
              p(slicedChunk)
            }

            pump()
          })
        }
        pump()
      }
    })

    const chunkedStreamReader = chunkedStream.getReader()

    const decryptedStream = new ReadableStream({
      start(ctrl) {

        function pump(i: number) {
          // @ts-ignore
          chunkedStreamReader.read().then(async res => {
            const { done, value } = res
            if (done || value === undefined) { ctrl.close(); return undefined; }

            const partIv = await c.deriveIv(iv, i)

            const decrypted = await c.decryptData(dataKey, partIv, value)

            ctrl.enqueue(new Uint8Array(decrypted))
            return pump(i + 1)
          })
        }

        return pump(0)
      }
    })

    return { data: decryptedStream, metadata, dataType }
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

  async changeSecret(newSecret: string): Promise<void> {

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