import { KeyStore } from '../src/keyStore'
import { BlindnetService, ServiceResponse, GetUserResponse, GetUsersPublicKeyResponse, GetDataKeyResponse } from '../src/blindnetService'
import { decodeJwtPayload, arr2b64 } from '../src/helper'

class TestKeyStore implements KeyStore {
  store = {}

  storeKey = (type, key) => {
    this.store[type] = key
    return Promise.resolve()
  }

  storeKeys = (privateKey, publicKey, aesKey) => {
    this.store['private'] = privateKey
    this.store['public'] = publicKey
    this.store['derived'] = aesKey
    return Promise.resolve()
  }

  getKey = (type) =>
    Promise.resolve(this.store[type])

  clear = () => {
    this.store = {}
    return Promise.resolve()
  }
}

class TestService implements BlindnetService {
  endpoint = ''
  jwt = undefined
  userId = undefined
  protocolVersion = 'v1.0'

  shouldFail = undefined
  expiredJwt = undefined

  users = {}
  docKeys = {}

  constructor(jwt, users, docKeys, shouldFail = false, expiredJwt = false) {
    this.jwt = jwt
    try { this.userId = decodeJwtPayload(jwt).userId = decodeJwtPayload(jwt).userId } catch { this.userId = 'temp' }
    this.shouldFail = shouldFail
    this.expiredJwt = expiredJwt
    this.users = users
    this.docKeys = docKeys
  }

  registerUser = (ePK, sPK, enc_eSK, enc_signSK, salt, signedJwt) => {
    if (this.shouldFail)
      return Promise.resolve<ServiceResponse<void>>({ type: 'Failed' })
    if (this.expiredJwt)
      return Promise.resolve<ServiceResponse<void>>({ type: 'AuthenticationNeeded' })

    this.users[this.jwt] = { user_id: this.userId, PK: arr2b64(ePK), eSK: arr2b64(enc_eSK), salt: arr2b64(salt) }
    return Promise.resolve<ServiceResponse<void>>({ type: 'Success', data: undefined })
  }

  getUserData = () => {
    const userData = this.users[this.jwt]
    if (userData == undefined)
      return Promise.resolve<ServiceResponse<GetUserResponse>>(
        { type: 'Success', data: { type: 'UserNotFound' } }
      )
    else
      return Promise.resolve<ServiceResponse<GetUserResponse>>(
        { type: 'Success', data: { type: 'UserFound', userData: { PK: userData.PK, eSK: userData.eSK, salt: userData.salt } } }
      )
  }

  getUsersPublicKey = (userId) => {
    // @ts-ignore
    const PK = Object.entries(users).find(u => u[1].user_id == userId)

    if (PK == undefined)
      return Promise.resolve<ServiceResponse<GetUsersPublicKeyResponse>>(
        { type: 'Success', data: { type: 'UserNotFound' } }
      )

    return Promise.resolve<ServiceResponse<GetUsersPublicKeyResponse>>(
      // @ts-ignore
      { type: 'Success', data: { type: 'UserFound', PK: PK[1].PK } }
    )
  }

  getGroupPublicKeys = () => {
    // @ts-ignore
    const data = Object.entries(users).map(u => { return { 'PK': u[1].PK, 'user_id': u[1].user_id } })
    return Promise.resolve<ServiceResponse<{ PK: string, user_id: string }[]>>(
      { type: 'Success', data }
    )
  }

  postEncryptedKeys = (encryptedKeys) => {
    const dataId = Math.random().toString()
    this.docKeys[dataId] = encryptedKeys
    return Promise.resolve<ServiceResponse<{ data_id: string }>>(
      { type: 'Success', data: { data_id: dataId } }
    )
  }

  getDataKey = (dataId) => {
    const key = this.docKeys[dataId].find(doc => doc.user_id == this.userId)

    if (key == undefined)
      return Promise.resolve<ServiceResponse<GetDataKeyResponse>>({ type: 'Success', data: { type: 'KeyNotFound' } })

    return Promise.resolve<ServiceResponse<GetDataKeyResponse>>(
      { type: 'Success', data: { type: 'KeyFound', key: key.eKey } }
    )
  }

  getDataKeys = () => {

    const data = Object.entries(this.docKeys).map(dKey => {
      return {
        data_id: dKey[0],
        // @ts-ignore
        eKey: dKey[1].find(d => d.user_id == this.userId).eKey
      }
    })

    return Promise.resolve<ServiceResponse<{ data_id: string, eKey: string }[]>>(
      { type: 'Success', data }
    )
  }

  updateUser = (eSK, salt) => {
    this.users[this.jwt] = { ...this.users[this.jwt], eSK, salt }
    return Promise.resolve<ServiceResponse<void>>({ type: 'Success', data: undefined })
  }

  giveAccess = (userId: string, docKeys: { data_id: string, eKey: string }[]) => {

    docKeys.forEach(rdk => {
      this.docKeys[rdk.data_id].push({ user_id: userId, eKey: rdk.eKey })
    })

    return Promise.resolve<ServiceResponse<void>>({ type: 'Success', data: undefined })
  }
}

export {
  TestKeyStore,
  TestService
}