import * as ed from 'noble-ed25519'
import { KeyStore, IndexedDbKeyStore } from './keyStore'
import { BlindnetService, BlindnetServiceHttp, ServiceResponse } from './blindnetService'
import * as error from './error'
import * as util from './util'
import * as cryptoUtil from './cryptoUtil'

type Bytes = Uint8Array | ArrayBuffer
type DataType = { type: 'STRING' } | { type: 'FILE', name: string } | { type: 'BYTES' }

function validateServiceResponse<T>(resp: ServiceResponse<T>, errorMsg: string): T {
  if (resp.type === 'AuthenticationNeeded')
    throw new error.AuthenticationError()
  else if (resp.type === 'Failed')
    throw new error.BlindnetServiceError(errorMsg)
  else
    return resp.data
}

class Blindnet {
  private service: BlindnetService
  private keyStore: KeyStore
  private static protocolVersion: string = "1"

  // #blindnet#
  private prefix = [35, 98, 108, 105, 110, 100, 110, 101, 116, 35]

  private constructor(service: BlindnetService, keyStore: KeyStore) {
    this.service = service
    this.keyStore = keyStore
  }

  static initTest(service: BlindnetService, keyStore: KeyStore) {
    return new Blindnet(service, keyStore)
  }

  static init(token: string, endpoint: string = 'https://api.blindnet.io') {
    const service = new BlindnetServiceHttp(token, endpoint, Blindnet.protocolVersion)
    const keyStore = new IndexedDbKeyStore()
    return new Blindnet(service, keyStore)
  }

  static disconnect() {
    (new IndexedDbKeyStore()).clear()
  }

  refreshToken(token: string) {
    this.service = new BlindnetServiceHttp(token, this.service.endpoint, Blindnet.protocolVersion)
  }

  static async deriveSecrets(password: string): Promise<{ blindnetPassword: string, appPassword: string }> {
    const passKey = await window.crypto.subtle.importKey(
      "raw",
      util.str2ab(password),
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

    return { blindnetPassword: util.arr2b64(blindnetPassBits), appPassword: util.arr2b64(appPassBits) }
  }

  async connect(password: string): Promise<void> {
    await this.keyStore.clear()

    const resp = await this.service.getUserData()
    const getUserResp = validateServiceResponse(resp, 'Fetching user data failed')

    switch (getUserResp.type) {
      case 'UserNotFound': {
        const encryptionKeyPair = await cryptoUtil.generateRandomRSAKeyPair(true)
        const signSK = ed.utils.randomPrivateKey()
        const signPK = await ed.getPublicKey(signSK)

        const encryptionPK = await window.crypto.subtle.exportKey("spki", encryptionKeyPair.publicKey)

        const salt = window.crypto.getRandomValues(new Uint8Array(16))
        const aesKey = await cryptoUtil.deriveAESKey(password, salt)

        const signedJwt = await ed.sign(new Uint8Array(util.str2ab(this.service.jwt)), signSK)
        const signedEncPK = await ed.sign(new Uint8Array(encryptionPK), signSK)

        // TODO
        const iv = new Uint8Array(12)
        const enc_encryptionSK = await cryptoUtil.wrapSecretKey(encryptionKeyPair.privateKey, aesKey, iv)
        const enc_signSK = await window.crypto.subtle.encrypt(
          { name: "AES-GCM", iv: iv },
          aesKey,
          util.concat(signSK, signPK)
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
          util.b642arr(enc_PK),
          { name: "RSA-OAEP", hash: "SHA-256" },
          true,
          ["encrypt"]
        )

        const aesKey = await cryptoUtil.deriveAESKey(password, util.b642arr(salt))

        const iv = new Uint8Array(12)

        const eSK = await util.rethrowPromise(
          () => window.crypto.subtle.unwrapKey(
            "jwk",
            util.b642arr(e_enc_SK),
            aesKey,
            { name: "AES-GCM", iv: iv },
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["decrypt", "unwrapKey"]
          ),
          new error.PasswordError()
        )
        const sSK =
          await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            aesKey,
            util.b642arr(e_sign_SK)
          )

        await this.keyStore.storeKeys(eSK, ePK, new Uint8Array(sSK).slice(0, 32), util.b642arr(sign_PK), aesKey)
        return undefined
      }
    }
  }

  async encrypt(data: string | File | Bytes, metadata?: { [key: string]: any }): Promise<{ dataId: string, encryptedData: ArrayBuffer }> {

    let metadataToEncrypt: any = metadata || {}
    let dataToEncrypt

    if (typeof metadataToEncrypt !== 'object')
      throw new error.BadFormatError('Metadata has to be an object')

    if (typeof data == 'string') {
      dataToEncrypt = util.str2ab(data)
      metadataToEncrypt = { ...metadataToEncrypt, dataType: { type: 'STRING' } }

    } else if (data instanceof File) {
      dataToEncrypt = await data.arrayBuffer()
      metadataToEncrypt = { ...metadataToEncrypt, dataType: { type: 'FILE', name: data.name } }

    } else if (data instanceof ArrayBuffer || data instanceof Uint8Array) {
      dataToEncrypt = data
      metadataToEncrypt = { ...metadataToEncrypt, dataType: { type: 'BYTES' } }
    } else {
      throw new error.BadFormatError('Encryption of provided data format is not supported')
    }

    const metadataBytes = util.str2ab(JSON.stringify(metadataToEncrypt))

    const resp = await this.service.getGroupPublicKeys()
    const users = validateServiceResponse(resp, 'Fetching public keys failed')

    if (users.length == 0)
      throw new error.NotEncryptabeError()

    const dataKey = await cryptoUtil.generateRandomAESKey(true)
    const iv = window.crypto.getRandomValues(new Uint8Array(12))

    const metadataLenBytes = util.getInt64Bytes(metadataBytes.byteLength)
    const allData = util.concat3(new Uint8Array(metadataLenBytes), metadataBytes, dataToEncrypt)

    const encrypted = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      dataKey,
      allData
    )

    const encryptedUserKeys = await Promise.all(
      users.map(async user => {

        const PK = await window.crypto.subtle.importKey(
          "spki",
          util.b642arr(user.publicEncryptionKey),
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

        return { userID: user.userID, encryptedSymmetricKey: util.arr2b64(encDataKey) }
      }))

    const postKeysResp = await this.service.postEncryptedKeys(encryptedUserKeys)
    const dataId = validateServiceResponse(postKeysResp, 'Could not upload the encrypted public keys')

    // string representation of dataId has 36 bytes (characters): 16 bytes x 2 for hex encoding and 4 hyphens
    const encryptedData = util.concat3(util.str2ab(dataId), iv.buffer, encrypted)

    return { dataId, encryptedData }
  }

  async encryptValues(data: { [key: string]: string }, noPrefix?: boolean): Promise<{ dataId: string, encryptedData: { [key: string]: string } }> {

    const resp = await this.service.getGroupPublicKeys()
    const users = validateServiceResponse(resp, 'Fetching public keys failed')

    if (users.length == 0)
      throw new error.NotEncryptabeError()

    const dataKey = await cryptoUtil.generateRandomAESKey(true)
    const seedIv = window.crypto.getRandomValues(new Uint8Array(12))

    const encryptedValues = await Promise.all(Object.entries(data).map(async field => {
      const key = field[0]
      const value = field[1]

      const iv = new Uint8Array(await window.crypto.subtle.digest('SHA-256', util.concat(util.str2ab(key), seedIv))).slice(0, 12)

      const encryptedValue = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        dataKey,
        util.str2ab(value)
      )

      const concatenated = noPrefix
        ? util.concat(iv, encryptedValue)
        // [#blindnet# - 10 bytes] [size - 8 bytes] [iv - 12 bytes] [encrypted_data]
        : util.concat3(new Uint8Array(this.prefix), new Uint8Array(util.getInt64Bytes(12 + encryptedValue.byteLength)), util.concat(iv, encryptedValue))

      return { key, encryptedValue: util.bytesToHex(concatenated) }
    }))

    const encryptedUserKeys = await Promise.all(
      users.map(async user => {

        const PK = await window.crypto.subtle.importKey(
          "spki",
          util.b642arr(user.publicEncryptionKey),
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

        return { userID: user.userID, encryptedSymmetricKey: util.arr2b64(encDataKey) }
      }))

    const postKeysResp = await this.service.postEncryptedKeys(encryptedUserKeys)
    const dataId = validateServiceResponse(postKeysResp, 'Could not upload the encrypted public keys')

    const encryptedData = encryptedValues.reduce((acc, cur) => {
      return { ...acc, [cur.key]: cur.encryptedValue }
    }, { dataId })

    return { dataId, encryptedData }
  }

  async decrypt(encryptedData: Bytes): Promise<{ data: string | File | Bytes, metadata: { dataType: DataType, [key: string]: any; } }> {

    const SK = await util.rethrowPromise(
      () => this.keyStore.getKey('private_enc'),
      new error.UserNotInitializedError('Private key not found')
    )

    const dataId = util.ab2str(encryptedData.slice(0, 36))

    const resp = await this.service.getDataKey(dataId)
    const eDataKeyResp = validateServiceResponse(resp, `Fetching data key failed for data with id ${dataId}`)

    if (eDataKeyResp.type === 'KeyNotFound')
      throw new error.NoAccessError(`A user has no access to data with id ${dataId}`)

    const eDataKey = eDataKeyResp.key

    const dataKey = await util.rethrowPromise(
      () => window.crypto.subtle.unwrapKey(
        "jwk",
        util.b642arr(eDataKey),
        SK,
        { name: "RSA-OAEP" },
        { name: "AES-GCM", length: 256 },
        false,
        ['decrypt']
      ),
      new error.EncryptionError(`Encrypted data key for data with id ${dataId} could not be decrypted`)
    )

    const allData = await util.rethrowPromise(
      () => window.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: encryptedData.slice(36, 48),
        },
        dataKey,
        encryptedData.slice(48)
      ),
      new error.EncryptionError(`Encrypted data with id ${dataId} could not be decrypted`)
    )

    const metadataLen = util.intFromBytes(Array.from(new Uint8Array(allData.slice(0, 8))))
    const metadataBytes = allData.slice(8, 8 + metadataLen)
    const dataBytes = allData.slice(8 + metadataLen)

    const metadata = JSON.parse(util.ab2str(metadataBytes))
    let data

    if (metadata.dataType.type === 'STRING') {
      data = util.ab2str(dataBytes)

    } else if (metadata.dataType.type === 'FILE') {
      data = new File([dataBytes], metadata.dataType.name)

    } else if (metadata.dataType.type === 'BYTES') {
      data = dataBytes
    }

    return { data: data, metadata: metadata }
  }

  async decryptValues(encryptedData: { [key: string]: string }, noPrefix?: boolean): Promise<{ data: { [key: string]: string } }> {

    const SK = await util.rethrowPromise(
      () => this.keyStore.getKey('private_enc'),
      new error.UserNotInitializedError('Private key not found')
    )

    const dataId = encryptedData.dataId

    if (dataId == undefined)
      throw new error.EncryptionError('dataId field missing from the input data')

    const resp = await this.service.getDataKey(dataId)
    const eDataKeyResp = validateServiceResponse(resp, `Fetching data key failed for data with id ${dataId}`)

    if (eDataKeyResp.type === 'KeyNotFound')
      throw new error.NoAccessError(`A user has no access to data with id ${dataId}`)

    const eDataKey = eDataKeyResp.key

    const dataKey = await util.rethrowPromise(
      () => window.crypto.subtle.unwrapKey(
        "jwk",
        util.b642arr(eDataKey),
        SK,
        { name: "RSA-OAEP" },
        { name: "AES-GCM", length: 256 },
        false,
        ['decrypt']
      ),
      new error.EncryptionError(`Encrypted data key for data with id ${dataId} could not be decrypted`)
    )

    const decryptedValues = await Promise.all(Object.entries(encryptedData).filter(x => x[0] !== 'dataId').map(async field => {
      const key = field[0]
      const encValue = util.hexToBytes(field[1])

      const iv = noPrefix
        ? encValue.slice(0, 12)
        : encValue.slice(this.prefix.length + 8, this.prefix.length + 8 + 12)

      const encData = noPrefix
        ? encValue.slice(12)
        : encValue.slice(this.prefix.length + 8 + 12)

      const decryptedValue = await util.rethrowPromise(
        () => window.crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: iv,
          },
          dataKey,
          encData
        ),
        new error.EncryptionError(`Encrypted values with id ${dataId} could not be decrypted`)
      )

      return { key, decryptedValue: util.ab2str(decryptedValue) }
    }))


    const data: { [key: string]: string } = decryptedValues.reduce((acc, cur) => {
      return { ...acc, [cur.key]: cur.decryptedValue }
    }, {})

    return { data: data }
  }

  async decryptStream(dataId: string, stream: ReadableStream<Uint8Array>): Promise<ReadableStream<Uint8Array>> {

    const SK = await util.rethrowPromise(
      () => this.keyStore.getKey('private_enc'),
      new error.UserNotInitializedError('Private key not found')
    )
    const resp = await this.service.getDataKey(dataId)
    const eDataKeyResp = validateServiceResponse(resp, `Fetching data key failed for data with id ${dataId}`)
    if (eDataKeyResp.type === 'KeyNotFound')
      throw new error.NoAccessError(`A user has no access to data with id ${dataId}`)
    const eDataKey = eDataKeyResp.key

    const dataKey = await util.rethrowPromise(
      () => window.crypto.subtle.unwrapKey(
        "jwk",
        util.b642arr(eDataKey),
        SK,
        { name: "RSA-OAEP" },
        { name: "AES-GCM", length: 256 },
        false,
        ['decrypt']
      ),
      new error.EncryptionError(`Encrypted data key for data with id ${dataId} could not be decrypted`)
    )

    const flag = [50, 51, 54, 50, 54, 67, 54, 57, 54, 69, 54, 52, 54, 69, 54, 53, 55, 52, 50, 51]

    function magic(arr, obj) {

      const { sf, fi, rl, il, bl, l, rd, dpi, di, d } = obj

      let searchingFlag = sf == undefined ? true : sf
      let flagIndex = fi == undefined ? 0 : fi

      let readingLen = rl == undefined ? false : rl
      let iLen = il == undefined ? 0 : il
      let byteLen = bl == undefined ? [] : bl
      let len = l

      let readingData = rd == undefined ? false : rd
      let dataPartIndex = dpi == undefined ? 0 : dpi
      let dataIndex = di == undefined ? 0 : di
      let data = d == undefined ? [] : d

      let partStartIndex = 0
      let parts = []

      for (let i = 0; i < arr.length; i++) {

        if (readingData) {
          data.push(arr[i])
          dataPartIndex++
          if (dataPartIndex == len * 2) {
            readingData = false
            dataPartIndex = 0
            len = 0
            searchingFlag = true

            const ddd = util.hexToBytes(util.ab2str(new Uint8Array(data)))

            parts.push({ encrypted: true, value: ddd })

            data = []
            i++
            partStartIndex = i
          }
        }

        if (readingLen) {
          byteLen.push(arr[i])
          iLen++
          if (iLen == 16) {
            len = util.intFromBytes(util.hexToBytes(util.ab2str(new Uint8Array(byteLen).buffer)))
            iLen = 0
            byteLen = []
            readingLen = false
            readingData = true
          }
        }

        if (searchingFlag) {
          if (arr[i] == flag[flagIndex]) {
            flagIndex++
            if (flagIndex == flag.length) {
              searchingFlag = false
              flagIndex = 0
              readingLen = true

              if (i > flag.length) {
                const part = arr.slice(partStartIndex, i - flag.length + 1)
                if (part.length > 0) {
                  parts.push({ encrypted: false, value: part })
                }
              }
            }
          } else {
            flagIndex = 0
          }
        }

      }

      const reading = readingLen || readingData

      if (!reading) {
        const part = arr.slice(partStartIndex, arr.length - flagIndex)
        if (part.length > 0) {
          parts.push({ encrypted: false, value: part })
        }
        // if (flagIndex > 0) {
        //   midFlag = true
        // }
      }

      return {
        reading,
        parts,
        sf: searchingFlag,
        fi: flagIndex,
        rl: readingLen,
        il: iLen,
        bl: byteLen,
        l: len,
        rd: readingData,
        dpi: dataPartIndex,
        di: dataIndex,
        d: data,
      }
    }

    let obj: { parts: { encrypted: boolean, value: Uint8Array }[] } = { parts: [] }

    const reader = stream.getReader()

    const newStream = new ReadableStream<Uint8Array>({
      start(controller) {
        return pump()

        async function pump() {
          const { done, value } = await reader.read()

          if (done) { controller.close(); return; }

          obj = magic(value, obj)

          for (let i = 0; i < obj.parts.length; i++) {
            const { encrypted, value } = obj.parts[i]

            if (encrypted) {
              const [iv, encData] = [value.slice(0, 12), value.slice(12)]

              const decryptedValue = await util.rethrowPromise(
                () => window.crypto.subtle.decrypt(
                  {
                    name: "AES-GCM",
                    iv: iv,
                  },
                  dataKey,
                  encData
                ),
                new error.EncryptionError(`Encrypted values with id ${dataId} could not be decrypted`)
              )

              controller.enqueue(new Uint8Array(decryptedValue))

            } else {
              controller.enqueue(value)
            }
          }

          return pump()
        }
      }
    })

    return newStream
  }

  // TODO: refactor repeating code
  async changePassword(newPassword: string, oldPassword?: string): Promise<void> {

    if (oldPassword == undefined) {

      const eSK = await util.rethrowPromise(
        () => this.keyStore.getKey('private_enc'),
        new error.UserNotInitializedError('Private key not found')
      )
      const sSK = await util.rethrowPromise(
        () => this.keyStore.getSignKey('private_sign'),
        new error.UserNotInitializedError('Private key not found')
      )
      const curPassKey = await util.rethrowPromise(
        () => this.keyStore.getKey('derived'),
        new error.UserNotInitializedError('Password derived key not found')
      )

      const salt = window.crypto.getRandomValues(new Uint8Array(16))
      const newPassKey = await cryptoUtil.deriveAESKey(newPassword, salt)
      // TODO:
      const iv = new Uint8Array(12)
      const encryptedESK = await cryptoUtil.wrapSecretKey(eSK, newPassKey, iv)
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
        throw new error.UserNotFoundError('')

      const { enc_PK, e_enc_SK, sign_PK, e_sign_SK, salt } = getUserResp.userData

      const ePK = await window.crypto.subtle.importKey(
        "spki",
        util.b642arr(enc_PK),
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"]
      )

      const aesKey = await cryptoUtil.deriveAESKey(oldPassword, util.b642arr(salt))

      const iv = new Uint8Array(12)

      const eSK = await util.rethrowPromise(
        () => window.crypto.subtle.unwrapKey(
          "jwk",
          util.b642arr(e_enc_SK),
          aesKey,
          { name: "AES-GCM", iv: iv },
          { name: "RSA-OAEP", hash: "SHA-256" },
          true,
          ["decrypt", "unwrapKey"]
        ),
        new error.PasswordError()
      )
      const sSK =
        await window.crypto.subtle.decrypt(
          { name: "AES-GCM", iv: iv },
          aesKey,
          util.b642arr(e_sign_SK)
        )

      const newSalt = window.crypto.getRandomValues(new Uint8Array(16))
      const newPassKey = await cryptoUtil.deriveAESKey(newPassword, newSalt)
      // TODO:
      const newIv = new Uint8Array(12)
      const encryptedESK = await cryptoUtil.wrapSecretKey(eSK, newPassKey, newIv)
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

    const SK = await util.rethrowPromise(
      () => this.keyStore.getKey('private_enc'),
      new error.UserNotInitializedError('Private key not found')
    )

    const resp1 = await this.service.getUsersPublicKey(userId)
    const userPKResp = validateServiceResponse(resp1, `Fetching the public key of a user ${userId} failed`)

    if (userPKResp.type == 'UserNotFound') {
      throw new error.UserNotFoundError(`User ${userId} not registered.`)
    }

    const resp2 = await this.service.getDataKeys()
    const encryptedDataKeys = validateServiceResponse(resp2, `Fetching the encrypted data keys failed`)

    const userPKspki = userPKResp.publicEncryptionKey

    const userPK = await window.crypto.subtle.importKey(
      "spki",
      util.b642arr(userPKspki),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["wrapKey"]
    )

    const updatedKeys = await Promise.all(
      encryptedDataKeys.map(async edk => {

        const dataKey = await util.rethrowPromise(
          () => window.crypto.subtle.unwrapKey(
            "jwk",
            util.b642arr(edk.encryptedSymmetricKey),
            SK,
            { name: "RSA-OAEP" },
            { name: "AES-GCM", length: 256 },
            true,
            ['decrypt']
          ),
          new error.EncryptionError(`Could not decrypt a data key for data id ${edk.documentID}`)
        )

        const newDataKey = await window.crypto.subtle.wrapKey(
          "jwk",
          dataKey,
          userPK,
          { name: "RSA-OAEP" }
        )

        return { documentID: edk.documentID, encryptedSymmetricKey: util.arr2b64(newDataKey) }
      }))

    const updateResp = await this.service.giveAccess(userId, updatedKeys)
    validateServiceResponse(updateResp, `Uploading the encrypted data keys for a user ${userId} failed`)

    return undefined
  }
}

export default {
  Blindnet,
  util: {
    toBase64: util.arr2b64,
    fromBase64: util.b642arr,
    toHex: util.bytesToHex,
    fromHex: util.hexToBytes
  },
  error
}