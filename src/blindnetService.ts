import {
  arr2b64
} from './util'

type ServiceResponse<T> =
  | { type: 'Success', data: T }
  | { type: 'AuthenticationNeeded' }
  | { type: 'Failed' }

type GetUserResponse =
  | { type: 'UserFound', userData: { enc_PK: string, e_enc_SK: string, sign_PK: string, e_sign_SK: string, salt: string } }
  | { type: 'UserNotFound' }

type GetUsersPublicKeyResponse =
  | { type: 'UserFound', publicEncryptionKey: string, publicSigningKey: string }
  | { type: 'UserNotFound' }

type GetDataKeyResponse =
  | { type: 'KeyFound', key: string }
  | { type: 'KeyNotFound' }

interface BlindnetService {
  endpoint: string
  jwt: string
  protocolVersion: string
  registerUser: (ePK: ArrayBuffer, sPK: ArrayBuffer, enc_eSK: ArrayBuffer, enc_sSK: ArrayBuffer, salt: Uint8Array, signedJwt: ArrayBuffer, signedEncPK: ArrayBuffer) => Promise<ServiceResponse<void>>
  getUserData: () => Promise<ServiceResponse<GetUserResponse>>
  getUsersPublicKey: (userId: string) => Promise<ServiceResponse<GetUsersPublicKeyResponse>>
  getGroupPublicKeys: () => Promise<ServiceResponse<{ publicEncryptionKey: string, userID: string }[]>>
  postEncryptedKeys: (encryptedKeys: { userID: string, encryptedSymmetricKey: string }[]) => Promise<ServiceResponse<string>>
  getDataKey: (dataId: string) => Promise<ServiceResponse<GetDataKeyResponse>>
  getDataKeys: () => Promise<ServiceResponse<{ documentID: string, encryptedSymmetricKey: string }[]>>
  updateUser: (esk: ArrayBuffer, ssk: ArrayBuffer, salt: Uint8Array) => Promise<ServiceResponse<void>>
  giveAccess: (userId: string, docKeys: { documentID: string, encryptedSymmetricKey: string }[]) => Promise<ServiceResponse<void>>
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

  registerUser: (
    ePK: ArrayBuffer,
    sPK: ArrayBuffer,
    enc_eSK: ArrayBuffer,
    enc_sSK: ArrayBuffer,
    salt: Uint8Array,
    signedJwt: ArrayBuffer,
    signedEncPK: ArrayBuffer
  ) => Promise<ServiceResponse<void>> =
    async (ePK, sPK, enc_eSK, enc_sSK, salt, signedJwt, signedEncPK) => {
      const resp =
        await fetch(`${this.endpoint}/api/v${this.protocolVersion}/users`, {
          method: 'POST',
          mode: 'cors',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.jwt}`
          },
          body: JSON.stringify({
            publicEncryptionKey: arr2b64(ePK),
            publicSigningKey: arr2b64(sPK),
            encryptedPrivateEncryptionKey: arr2b64(enc_eSK),
            encryptedPrivateSigningKey: arr2b64(enc_sSK),
            keyDerivationSalt: arr2b64(salt),
            signedJwt: arr2b64(signedJwt),
            signedPublicEncryptionKey: arr2b64(signedEncPK)
          })
        })

      return await handleResponse<void>(resp, _ => undefined)
    }

  getUserData: () => Promise<ServiceResponse<GetUserResponse>> = async () => {
    const resp = await fetch(`${this.endpoint}/api/v${this.protocolVersion}/keys/me`, {
      method: 'GET',
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.jwt}`
      }
    })

    function mapping(data: any): GetUserResponse {
      return {
        type: 'UserFound',
        userData: {
          enc_PK: data.publicEncryptionKey,
          e_enc_SK: data.encryptedPrivateEncryptionKey,
          sign_PK: data.publicSigningKey,
          e_sign_SK: data.encryptedPrivateSigningKey,
          salt: data.keyDerivationSalt
        }
      }
    }

    return await handleResponse<GetUserResponse>(resp, mapping, { type: 'UserNotFound' })
  }

  getUsersPublicKey: (userId: string) => Promise<ServiceResponse<GetUsersPublicKeyResponse>> = async (userId) => {
    const resp = await fetch(`${this.endpoint}/api/v${this.protocolVersion}/keys/${userId}`, {
      method: 'GET',
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.jwt}`
      }
    })

    function mapping(data: any): GetUsersPublicKeyResponse {
      return {
        type: 'UserFound',
        publicEncryptionKey: data.publicEncryptionKey,
        publicSigningKey: data.publicSigningKey
      }
    }

    return await handleResponse<GetUsersPublicKeyResponse>(resp, mapping, { type: 'UserNotFound' })
  }

  getGroupPublicKeys: () => Promise<ServiceResponse<{ publicEncryptionKey: string, userID: string }[]>> = async () => {
    const resp =
      await fetch(`${this.endpoint}/api/v${this.protocolVersion}/keys`, {
        method: 'GET',
        mode: 'cors',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.jwt}`
        }
      })

    return await handleResponse<{ publicEncryptionKey: string, userID: string }[]>(resp, x => x)
  }

  postEncryptedKeys: (encryptedKeys: { userID: string, encryptedSymmetricKey: string }[]) => Promise<ServiceResponse<string>> = async (encryptedKeys) => {
    const resp = await fetch(`${this.endpoint}/api/v${this.protocolVersion}/documents`, {
      method: 'POST',
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.jwt}`
      },
      body: JSON.stringify(encryptedKeys)
    })

    return await handleResponse<string>(resp, x => x)
  }

  getDataKey: (dataId: string) => Promise<ServiceResponse<GetDataKeyResponse>> = async (dataId) => {
    const resp = await fetch(`${this.endpoint}/api/v${this.protocolVersion}/documents/keys/${dataId}`, {
      method: 'GET',
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.jwt}`
      }
    })

    function mapping(data: any): GetDataKeyResponse {
      return { type: 'KeyFound', key: data }
    }

    return await handleResponse<GetDataKeyResponse>(resp, mapping, { type: 'KeyNotFound' })
  }

  getDataKeys: () => Promise<ServiceResponse<{ documentID: string, encryptedSymmetricKey: string }[]>> = async () => {
    const resp = await fetch(`${this.endpoint}/api/v${this.protocolVersion}/documents/keys`, {
      method: 'GET',
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.jwt}`
      }
    })

    return await handleResponse<{ documentID: string, encryptedSymmetricKey: string }[]>(resp, x => x)
  }

  updateUser: (esk: ArrayBuffer, ssk: ArrayBuffer, salt: Uint8Array) => Promise<ServiceResponse<void>> = async (esk, ssk, salt) => {
    const resp = await fetch(`${this.endpoint}/api/v${this.protocolVersion}/keys/me`, {
      method: 'PUT',
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.jwt}`
      },
      body: JSON.stringify({
        encryptedPrivateEncryptionKey: arr2b64(esk),
        encryptedPrivateSigningKey: arr2b64(ssk),
        keyDerivationSalt: arr2b64(salt)
      })
    })

    return await handleResponse<void>(resp, _ => undefined)
  }

  giveAccess: (userId: string, docKeys: { documentID: string, encryptedSymmetricKey: string }[]) => Promise<ServiceResponse<void>> = async (userId, docKeys) => {
    const resp = await fetch(`${this.endpoint}/api/v${this.protocolVersion}/documents/keys/user/${userId}`, {
      method: 'PUT',
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.jwt}`
      },
      body: JSON.stringify(docKeys)
    })

    return await handleResponse<void>(resp, _ => undefined)
  }
}

async function handleResponse<T>(resp: Response, f: (_: any) => T, notFoundData?: any): Promise<ServiceResponse<T>> {
  switch (resp.status) {
    case 200: {
      // TODO: handle parsing errors
      const body = await resp.json()
      return { type: 'Success', data: f(body) }
    }
    case 401:
      return { type: 'AuthenticationNeeded' }
    case 400: // TODO: fix on BE
    case 404: {
      if (notFoundData != undefined)
        return { type: 'Success', data: notFoundData }
      else
        return { type: 'Failed' }
    }
    default:
      return { type: 'Failed' }
  }
}

export {
  BlindnetService,
  BlindnetServiceHttp,
  ServiceResponse,
  GetUserResponse,
  GetUsersPublicKeyResponse,
  GetDataKeyResponse
}
