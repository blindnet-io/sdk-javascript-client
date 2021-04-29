import { KeyStore } from '../src/keyStore'
import { BlindnetService, ServiceResponse, GetUserResponse, GetUsersPublicKeyResponse, GetDataKeyResponse } from '../src/blindnetService'
import { decodeJwtPayload, arr2b64 } from '../src/helper'

class TestKeyStore implements KeyStore {
  store = {}

  storeKey = (type, key) => {
    this.store[type] = key
    return Promise.resolve()
  }

  storeKeys = (privateEnc, publicEnc, privateSign, publicSign, aes) => {
    this.store['private_enc'] = privateEnc
    this.store['public_enc'] = publicEnc
    this.store['private_sign'] = privateSign
    this.store['public_sign'] = publicSign
    this.store['derived'] = aes
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
  protocolVersion = '1'

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

  registerUser = (ePK, sPK, enc_eSK, enc_signSK, salt, signedJwt, signedEncPK) => {
    if (this.shouldFail)
      return Promise.resolve<ServiceResponse<void>>({ type: 'Failed' })
    if (this.expiredJwt)
      return Promise.resolve<ServiceResponse<void>>({ type: 'AuthenticationNeeded' })

    this.users[this.jwt] = {
      user_id: this.userId,
      enc_PK: arr2b64(ePK),
      e_enc_SK: arr2b64(enc_eSK),
      sign_PK: arr2b64(sPK),
      e_sign_SK: arr2b64(enc_signSK),
      salt: arr2b64(salt)
    }
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
        {
          type: 'Success', data: {
            type: 'UserFound', userData: {
              enc_PK: userData.enc_PK,
              e_enc_SK: userData.e_enc_SK,
              sign_PK: userData.sign_PK,
              e_sign_SK: userData.e_sign_SK,
              salt: userData.salt
            }
          }
        }
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
      { type: 'Success', data: { type: 'UserFound', PK: PK[1].enc_PK } }
    )
  }

  getGroupPublicKeys = () => {
    // @ts-ignore
    const data = Object.entries(users).map(u => { return { 'PK': u[1].enc_PK, 'user_id': u[1].user_id } })
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

  updateUser = (esk, ssk, salt) => {
    this.users[this.jwt] = { ...this.users[this.jwt], e_enc_SK: esk, e_sign_SK: ssk, salt }
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