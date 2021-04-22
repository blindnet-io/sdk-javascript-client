import {
  arr2b64
} from './helper'

type ServiceResponse<T> =
  | { type: 'Success', data: T }
  | { type: 'AuthenticationNeeded' }
  | { type: 'Failed' }

type GetUserResponse =
  | { type: 'UserFound', userData: { PK: string, eSK: string, salt: string } }
  | { type: 'UserNotFound' }

type GetUsersPublicKeyResponse =
  | { type: 'UserFound', PK: string }
  | { type: 'UserNotFound' }

type GetDataKeyResponse =
  | { type: 'KeyFound', key: string }
  | { type: 'KeyNotFound' }

interface BlindnetService {
  endpoint: string
  jwt: string
  protocolVersion: string
  initializeUser: (ePK: ArrayBuffer, sPK: ArrayBuffer, enc_eSK: ArrayBuffer, enc_signSK: ArrayBuffer, salt: Uint8Array, signedJwt: ArrayBuffer) => Promise<ServiceResponse<void>>
  getUserData: () => Promise<ServiceResponse<GetUserResponse>>
  getUsersPublicKey: (userId: string) => Promise<ServiceResponse<GetUsersPublicKeyResponse>>
  getGroupPublicKeys: () => Promise<ServiceResponse<{ PK: string, user_id: string }[]>>
  postEncryptedKeys: (encryptedKeys: { user_id: string, eKey: string }[]) => Promise<ServiceResponse<{ data_id: string }>>
  getDataKey: (dataId: string) => Promise<ServiceResponse<GetDataKeyResponse>>
  getDataKeys: () => Promise<ServiceResponse<{ data_id: string, eKey: string }[]>>
  updateUser: (esk: ArrayBuffer, salt: Uint8Array) => Promise<ServiceResponse<void>>
  giveAccess: (userId: string, docKeys: { data_id: string, eKey: string }[]) => Promise<ServiceResponse<void>>
}

class BlindnetServiceHttp implements BlindnetService {
  endpoint: string = undefined
  protocolVersion: string = undefined
  jwt: string = undefined

  constructor(jwt: string, endpoint: string, protocolVersion: string) {
    this.jwt = jwt
    this.endpoint = endpoint
    this.protocolVersion = protocolVersion
  }

  initializeUser: (ePK: ArrayBuffer, sPK: ArrayBuffer, enc_eSK: ArrayBuffer, enc_signSK: ArrayBuffer, salt: Uint8Array, signedJwt: ArrayBuffer) => Promise<ServiceResponse<void>> =
    async (ePK, sPK, enc_eSK, enc_signSK, salt, signedJwt) => {
      const resp =
        await fetch(`${this.endpoint}/v${this.protocolVersion}/initUser`, {
          method: 'POST',
          mode: 'cors',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.jwt}`
          },
          body: JSON.stringify({
            encryption_public_key: arr2b64(ePK),
            sign_public_key: arr2b64(sPK),
            encrypted_encryption_private_key: arr2b64(enc_eSK),
            encrypted_sing_private_key: arr2b64(enc_signSK),
            salt: arr2b64(salt),
            signedJwt: arr2b64(signedJwt)
          })
        })

      return await handleResponse<void>(resp, _ => undefined)
    }

  getUserData: () => Promise<ServiceResponse<GetUserResponse>> = async () => {
    const resp = await fetch(`${this.endpoint}/v${this.protocolVersion}/getUser`, {
      method: 'POST',
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.jwt}`
      },
      body: JSON.stringify({})
    })

    function mapping(data: any): GetUserResponse {
      switch (data.type) {
        case 'UserNotFound':
          return { type: 'UserNotFound' }
        case 'UserFound':
          return {
            type: 'UserFound',
            userData: {
              PK: data.userData.encryption_public_key,
              eSK: data.userData.encrypted_encryption_secret_key,
              salt: data.userData.salt
            }
          }
      }
    }

    return await handleResponse<GetUserResponse>(resp, mapping)
  }

  getUsersPublicKey: (userId: string) => Promise<ServiceResponse<GetUsersPublicKeyResponse>> = async (userId) => {
    const resp = await fetch(`${this.endpoint}/v${this.protocolVersion}/getUsersPublicKey`, {
      method: 'POST',
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.jwt}`
      },
      body: JSON.stringify({ user_id: userId })
    })

    function mapping(data: any): GetUsersPublicKeyResponse {
      switch (data.type) {
        case 'UserNotFound':
          return { type: 'UserNotFound' }
        case 'UserFound':
          return {
            type: 'UserFound',
            PK: data.PK
          }
      }
    }

    return await handleResponse<GetUsersPublicKeyResponse>(resp, mapping)
  }

  getGroupPublicKeys: () => Promise<ServiceResponse<{ PK: string, user_id: string }[]>> = async () => {
    const resp =
      await fetch(`${this.endpoint}/v${this.protocolVersion}/getPKs`, {
        method: 'POST',
        mode: 'cors',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.jwt}`
        },
        body: JSON.stringify({})
      })

    return await handleResponse<{ PK: string, user_id: string }[]>(resp, x => x)
  }

  postEncryptedKeys: (encryptedKeys: { user_id: string, eKey: string }[]) => Promise<ServiceResponse<{ data_id: string }>> = async (encryptedKeys) => {
    const resp = await fetch(`${this.endpoint}/v${this.protocolVersion}/postEncryptedKeys`, {
      method: 'POST',
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.jwt}`
      },
      body: JSON.stringify(encryptedKeys)
    })

    return await handleResponse<{ data_id: string }>(resp, x => x)
  }

  getDataKey: (dataId: string) => Promise<ServiceResponse<GetDataKeyResponse>> = async (dataId) => {
    const resp = await fetch(`${this.endpoint}/v${this.protocolVersion}/getdataKey`, {
      method: 'POST',
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.jwt}`
      },
      body: JSON.stringify({ data_id: dataId })
    })

    function mapping(data: any): GetDataKeyResponse {
      switch (data.type) {
        case 'KeyNotFound':
          return { type: 'KeyNotFound' }
        case 'KeyFound':
          return {
            type: 'KeyFound',
            key: data.key
          }
      }
    }

    return await handleResponse<GetDataKeyResponse>(resp, mapping)
  }

  getDataKeys: () => Promise<ServiceResponse<{ data_id: string, eKey: string }[]>> = async () => {
    const resp = await fetch(`${this.endpoint}/v${this.protocolVersion}/getUserKeys`, {
      method: 'POST',
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.jwt}`
      },
      body: JSON.stringify({})
    })

    return await handleResponse<{ data_id: string, eKey: string }[]>(resp, x => x)
  }

  updateUser: (esk: ArrayBuffer, salt: Uint8Array) => Promise<ServiceResponse<void>> = async (esk, salt) => {
    const resp = await fetch(`${this.endpoint}/v${this.protocolVersion}/updateUser`, {
      method: 'POST',
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.jwt}`
      },
      body: JSON.stringify({
        eSK: arr2b64(esk),
        salt: arr2b64(salt)
      })
    })

    return await handleResponse<void>(resp, _ => undefined)
  }

  giveAccess: (userId: string, docKeys: { data_id: string, eKey: string }[]) => Promise<ServiceResponse<void>> = async (userId, docKeys) => {
    const resp = await fetch(`${this.endpoint}/v${this.protocolVersion}/giveAccess`, {
      method: 'POST',
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.jwt}`
      },
      body: JSON.stringify({
        user_id: userId,
        docKeys: docKeys
      })
    })

    return await handleResponse<void>(resp, _ => undefined)
  }
}

async function handleResponse<T>(resp: Response, f: (_: any) => T): Promise<ServiceResponse<T>> {
  switch (resp.status) {
    case 200: {
      // TODO: handle parsing errors
      const body = await resp.json()
      return { type: 'Success', data: f(body) }
    }
    case 401:
      return { type: 'AuthenticationNeeded' }
    default:
      return { type: 'Failed' }
  }
}

export {
  BlindnetService,
  BlindnetServiceHttp
}
