import {
  get,
  set,
  getMany,
  setMany,
  del,
  clear,
  createStore,
} from 'idb-keyval'
import {
  str2ab,
  b64url2arr,
  arr2b64url,
  decodeJwtPayload,
  concat
} from './helper'

type Data = Uint8Array | ArrayBuffer

type ServiceResponse<T> =
  | { type: 'Success', data: T }
  | { type: 'Failed' }

type GetUserResponse =
  | { type: 'UserFound', userData: { PK: string, eSK: string, salt: string } }
  | { type: 'UserNotFound' }
  | { type: 'Error' }

interface BlindnetService {
  initializeUser: (pk: ArrayBuffer, esk: ArrayBuffer, salt: Uint8Array, id?: any) => Promise<ServiceResponse<void>>
  getUserData: (id?: any) => Promise<GetUserResponse>
  getUsersPublicKey: (userId: string) => Promise<ServiceResponse<{ PK: string }>>
  getGroupPublicKeys: (id?: any) => Promise<ServiceResponse<{ PK: string, user_id: string }[]>>
  postEncryptedKeys: (encryptedKeys: { user_id: string, eKey: string }[]) => Promise<ServiceResponse<{ data_id: string }>>
  getDataKey: (dataId: string, userId?: string) => Promise<ServiceResponse<{ key: string }>>
  getDataKeys: (userId?: string) => Promise<ServiceResponse<{ data_id: string, eKey: string }[]>>
  updateUser: (esk: ArrayBuffer, salt: Uint8Array, userId?: string) => Promise<ServiceResponse<void>>
  giveAccess: (userId: string, docKeys: { data_id: string, eKey: string }[]) => Promise<ServiceResponse<void>>
}

class BlindnetServiceHttp implements BlindnetService {
  private endpoint = 'http://localhost:9000'
  private jwt: string = undefined

  constructor(jwt: string) {
    this.jwt = jwt
  }

  initializeUser: (pk: ArrayBuffer, esk: ArrayBuffer, salt: Uint8Array) => Promise<ServiceResponse<void>> = async (pk, esk, salt) => {
    const resp =
      await fetch(`${this.endpoint}/initUser`, {
        method: 'POST',
        mode: 'cors',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          jwt: this.jwt,
          PK: arr2b64url(pk),
          eSK: arr2b64url(esk),
          salt: arr2b64url(salt)
        })
      })

    // TODO: repeating
    switch (resp.status) {
      case 200:
        return { type: 'Success', data: undefined }
      default:
        return { type: 'Failed' }
    }
  }

  getUserData: () => Promise<GetUserResponse> = async () => {
    const resp = await fetch(`${this.endpoint}/getUser`, {
      method: 'POST',
      mode: 'cors',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jwt: this.jwt })
    })

    switch (resp.status) {
      case 200: {
        const data = await resp.json()
        return { type: 'UserFound', userData: data }
      }
      case 404:
        return { type: 'UserNotFound' }
      default:
        return { type: 'Error' }
    }
  }

  getUsersPublicKey: (userId: string) => Promise<ServiceResponse<{ PK: string }>> = async (userId) => {
    const resp = await fetch(`${this.endpoint}/getUsersPublicKey`, {
      method: 'POST',
      mode: 'cors',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jwt: this.jwt, user_id: userId })
    })

    switch (resp.status) {
      case 200: {
        const data = await resp.json()
        return { type: 'Success', data: data }
      }
      default:
        return { type: 'Failed' }
    }
  }

  getGroupPublicKeys: () => Promise<ServiceResponse<{ PK: string, user_id: string }[]>> = async () => {
    const resp =
      await fetch(`${this.endpoint}/getPKs`, {
        method: 'POST',
        mode: 'cors',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jwt: this.jwt })
      })

    switch (resp.status) {
      case 200: {
        const data = await resp.json()
        return { type: 'Success', data }
      }
      default:
        return { type: 'Failed' }
    }
  }

  postEncryptedKeys: (encryptedKeys: { user_id: string, eKey: string }[]) => Promise<ServiceResponse<{ data_id: string }>> = async (encryptedKeys) => {
    const resp = await fetch(`${this.endpoint}/postEncryptedKeys`, {
      method: 'POST',
      mode: 'cors',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(encryptedKeys)
    })

    switch (resp.status) {
      case 200: {
        const data = await resp.json()
        return { type: 'Success', data: data }
      }
      default:
        return { type: 'Failed' }
    }
  }

  getDataKey: (dataId: string) => Promise<ServiceResponse<{ key: string }>> = async (dataId) => {
    const resp = await fetch(`${this.endpoint}/getdataKey`, {
      method: 'POST',
      mode: 'cors',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jwt: this.jwt, data_id: dataId })
    })

    switch (resp.status) {
      case 200: {
        const data = await resp.json()
        return { type: 'Success', data: data }
      }
      default:
        return { type: 'Failed' }
    }
  }

  getDataKeys: () => Promise<ServiceResponse<{ data_id: string, eKey: string }[]>> = async () => {
    const resp = await fetch(`${this.endpoint}/getUserKeys`, {
      method: 'POST',
      mode: 'cors',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jwt: this.jwt })
    })

    switch (resp.status) {
      case 200: {
        const data = await resp.json()
        return { type: 'Success', data: data }
      }
      default:
        return { type: 'Failed' }
    }
  }

  updateUser: (esk: ArrayBuffer, salt: Uint8Array) => Promise<ServiceResponse<void>> = async (esk, salt) => {
    const resp = await fetch(`${this.endpoint}/updateUser`, {
      method: 'POST',
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        jwt: this.jwt,
        eSK: arr2b64url(esk),
        salt: arr2b64url(salt)
      })
    })

    switch (resp.status) {
      case 200:
        return { type: 'Success', data: undefined }
      default:
        return { type: 'Failed' }
    }
  }

  giveAccess: (userId: string, docKeys: { data_id: string, eKey: string }[]) => Promise<ServiceResponse<void>> = async (userId, docKeys) => {
    const resp = await fetch(`${this.endpoint}/giveAccess`, {
      method: 'POST',
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        jwt: this.jwt,
        user_id: userId,
        docKeys: docKeys
      })
    })

    switch (resp.status) {
      case 200:
        return { type: 'Success', data: undefined }
      default:
        return { type: 'Failed' }
    }
  }
}

interface KeyStore {
  storeKey: (type: string, key: CryptoKey) => Promise<void>
  storeKeys: (privateKey: CryptoKey, publicKey: CryptoKey, aesKey: CryptoKey) => Promise<void>
  getKey: (type: string) => Promise<CryptoKey>
  clear: () => Promise<void>
}

class IndexedDbKeyStore implements KeyStore {
  store = createStore('blindnetKeys', 'keys')

  storeKey = (type, key) =>
    set(type, key, this.store)

  storeKeys = (privateKey, publicKey, aesKey) =>
    setMany([['private', privateKey], ['public', publicKey], ['derived', aesKey]], this.store)

  getKey = (type) =>
    get(type, this.store)

  clear = () => clear(this.store)
}


class BlindnetSdk {
  private jwt = undefined
  private service: BlindnetService = undefined
  private keyStore: KeyStore = undefined

  private constructor(jwt: string) {
    this.jwt = jwt
    this.service = new BlindnetServiceHttp(jwt)
    this.keyStore = new IndexedDbKeyStore()
  }

  static init(jwt: string) {
    return new BlindnetSdk(jwt)
  }

  //
  // TODO: update service n stuff
  //
  //
  refreshJwt(jwt: string) {
    this.jwt = jwt
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
          b64url2arr(PKspki),
          { name: "RSA-OAEP", hash: "SHA-256" },
          true,
          ["encrypt"]
        )

        const aesKey = await deriveAESKey(passphrase, b64url2arr(salt))

        const iv = new Uint8Array(12)
        const SK = await window.crypto.subtle.unwrapKey(
          "pkcs8",
          b64url2arr(eSK),
          aesKey,
          { name: "AES-GCM", iv: iv },
          { name: "RSA-OAEP", hash: "SHA-256" },
          true,
          ["decrypt", "unwrapKey"]
        )

        await this.keyStore.clear()
        await this.keyStore.storeKeys(SK, PK, aesKey)
        return undefined
      }
      case 'Error': {
        // todo
        throw new Error("")
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
              b64url2arr(user.PK),
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

            return { user_id: user.user_id, eKey: arr2b64url(encDataKey) }
          }))

        const postKeysResp = await this.service.postEncryptedKeys(encryptedUserKeys)

        switch (postKeysResp.type) {
          case 'Success': {
            return { dataId: postKeysResp.data.data_id, encryptedData: encryptedDataWithIV, encryptedMetadata: encryptedMetadataWithIV }
          }
          case 'Failed': {
            // todo
            throw new Error("")
          }
        }
      }
      case 'Failed': {
        // todo
        throw new Error("")
      }
    }
  }

  async decrypt(dataId: string, encryptedData: Data, encryptedMetadata?: Data): Promise<{ data: ArrayBuffer, metadata: ArrayBuffer }> {
    const eDataKeyResp = await this.service.getDataKey(dataId)

    switch (eDataKeyResp.type) {
      case 'Success': {
        const eDataKey = eDataKeyResp.data.key
        const SK = await this.keyStore.getKey('private')

        const dataKey = await window.crypto.subtle.unwrapKey(
          "jwk",
          b64url2arr(eDataKey),
          SK,
          { name: "RSA-OAEP" },
          { name: "AES-GCM", length: 256 },
          false,
          ['decrypt']
        )

        const data = await window.crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: encryptedData.slice(0, 12),
          },
          dataKey,
          encryptedData.slice(12)
        )

        let metadata = new ArrayBuffer(0)
        if (encryptedMetadata != undefined) {
          metadata = await window.crypto.subtle.decrypt(
            {
              name: "AES-GCM",
              iv: encryptedMetadata.slice(0, 12),
            },
            dataKey,
            encryptedMetadata.slice(12)
          )
        }

        return { data: data, metadata: metadata }
      }
      case 'Failed': {
        // todo
        throw new Error("")
      }
    }
  }

  async updatePassphrase(newPassphrase: string): Promise<void> {
    const SK = await this.keyStore.getKey('private')
    const curPassKey = await this.keyStore.getKey('derived')

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
        // todo
        throw new Error("")
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
            const SK = await this.keyStore.getKey('private')
            const userPKspki = userPKResp.data.PK

            const userPK = await window.crypto.subtle.importKey(
              "spki",
              b64url2arr(userPKspki),
              { name: "RSA-OAEP", hash: "SHA-256" },
              false,
              ["wrapKey"]
            )

            const updatedKeys = await Promise.all(
              encryptedDataKeysResp.data.map(async edk => {

                const dataKey = await window.crypto.subtle.unwrapKey(
                  "jwk",
                  b64url2arr(edk.eKey),
                  SK,
                  { name: "RSA-OAEP" },
                  { name: "AES-GCM", length: 256 },
                  true,
                  ['decrypt']
                )

                const newDataKey = await window.crypto.subtle.wrapKey(
                  "jwk",
                  dataKey,
                  userPK,
                  { name: "RSA-OAEP" }
                )

                return { data_id: edk.data_id, eKey: arr2b64url(newDataKey) }
              }))

            const updateRes = await this.service.giveAccess(userId, updatedKeys)

            switch (updateRes.type) {
              case 'Success': {
                return undefined
              }
              case 'Failed': {
                // todo
                throw new Error("")
              }
            }
          }
          case 'Failed': {
            // todo
            throw new Error("")
          }
        }
      }
      case 'Failed': {
        // todo
        throw new Error("")
      }
    }
  }
}

// FR-SDK01
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
      iterations: 250000,
      hash: "SHA-256",
    },
    passKey,
    { name: "AES-GCM", length: 256 },
    exportable,
    ["wrapKey", "unwrapKey"]
  )

  return aesKey
}
// FR-SDK01
async function generateRandomAESKey(exportable: boolean = false): Promise<CryptoKey> {
  const key = await window.crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    exportable,
    ["encrypt", "decrypt"]
  )

  return key
}
// FR-SDK01
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
// FR-SDK03
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

async function asd(n: number) {
  if (n == 0) return
  else if (n % 2 == 0) await test(true)
  else await test(false)
  return asd(n - 1)
}

asd(1)

async function test(swap: boolean = false) {
  const jwt1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJ1c2VyMCIsImhvdGV0SWQiOiJob3RlbDAiLCJpYXQiOjE1MTYyMzkwMjJ9.4KCp00fun1Drhh0QeuDkn-GEIm3XNZVS8hZMGSFMEGU"
  const jwt2 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJ1c2VyMSIsImhvdGV0SWQiOiJob3RlbDAiLCJpYXQiOjE1MTYyMzkwMjJ9.SWD8ihR-QJDcvBvBWjzrOKrGNTUd2ZSkIIlr2Il4WkA"
  const otjwt1 = ""
  let pass1a = 'pass1'
  let pass1b = 'fjsdlkjflkds'
  let pass2a = 'asd'
  let pass2b = 'fjsldjflkds'

  if (swap) {
    let temp: string = undefined
    temp = pass1a
    pass1a = pass1b
    pass1b = temp
  }

  console.log('STARTING')

  let blindnet = BlindnetSdk.init(jwt1)
  await blindnet.initUser(pass1a)
  console.log('initialized user 1')
  await blindnet.initUser(pass1a)
  console.log('loaded user 1')
  await blindnet.initUser(pass1a)
  console.log('loaded user 1 again')

  // blindnet = BlindnetSdk.init(jwt2)
  // await blindnet.initUser(pass2a)
  // console.log('initialized user 2')

  blindnet = BlindnetSdk.init(otjwt1)
  console.log('started unregistered user')

  const encData = await blindnet.encrypt(str2ab('sup bro?'), str2ab('{ "name": "asd" }'))
  console.log('encrypted', encData)

  blindnet = BlindnetSdk.init(jwt1)
  await blindnet.initUser(pass1a)
  console.log('user 1 loaded')
  const decData = await blindnet.decrypt(encData.dataId, encData.encryptedData, encData.encryptedMetadata)
  console.log("data:        ", String.fromCharCode.apply(null, new Uint16Array(decData.data)))
  console.log("metadata:    ", JSON.parse(String.fromCharCode.apply(null, new Uint16Array(decData.metadata))))

  blindnet = BlindnetSdk.init(jwt2)
  await blindnet.initUser(pass2a)
  console.log('initialized user 2')

  blindnet = BlindnetSdk.init(jwt1)
  await blindnet.initUser(pass1a)
  console.log('user 1 loaded')

  await blindnet.giveAccess('user1')
  console.log('gave access to user 2')

  blindnet = BlindnetSdk.init(jwt2)
  await blindnet.initUser(pass2a)
  console.log('user 2 loaded')
  const decData2 = await blindnet.decrypt(encData.dataId, encData.encryptedData, encData.encryptedMetadata)
  console.log("data:        ", String.fromCharCode.apply(null, new Uint16Array(decData.data)))
  console.log("metadata:    ", JSON.parse(String.fromCharCode.apply(null, new Uint16Array(decData.metadata))))

  // await blindnet.updatePassphrase(pass1b)
  // console.log('user 1 pass updated')

  console.log('\n\n')
}