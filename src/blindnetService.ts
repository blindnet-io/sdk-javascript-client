import {
  bin2b64str
} from './util'

type ServiceResponse<T> =
  | { type: 'Success', data: T }
  | { type: 'AuthenticationNeeded' }
  | { type: 'Failed' }

type GetUserResponse =
  | { type: 'UserFound', userData: { enc_PK: string, e_enc_SK: string, sign_PK: string, e_sign_SK: string, salt: string } }
  | { type: 'UserNotFound' }

type registerUserF =
  (
    encryptionPublicKey: ArrayBuffer,
    signingPublicKey: ArrayBuffer,
    encryptedEncryptionSecretKey: ArrayBuffer,
    encryptedSigningSecretKey: ArrayBuffer,
    salt: Uint8Array,
    signedToken: ArrayBuffer,
    signedEncryptionPublicKey: ArrayBuffer
  )
    => Promise<ServiceResponse<void>>

interface BlindnetService {
  token: string
  protocolVersion: string
  registerUser: registerUserF
  getUserData: () => Promise<ServiceResponse<GetUserResponse>>
  getUsersPublicKey: (userId: string) => Promise<ServiceResponse<{ publicEncryptionKey: string, publicSigningKey: string }>>
  getPublicKeys: (userIds: string[]) => Promise<ServiceResponse<{ publicEncryptionKey: string, userID: string }[]>>
  getGroupPublicKeys: (groupId: string) => Promise<ServiceResponse<{ publicEncryptionKey: string, userID: string }[]>>
  postEncryptedKeys: (encryptedKeys: { userID: string, encryptedSymmetricKey: string }[]) => Promise<ServiceResponse<string>>
  getDataKey: (dataId: string) => Promise<ServiceResponse<string>>
  getAllDataKeys: () => Promise<ServiceResponse<{ documentID: string, encryptedSymmetricKey: string }[]>>
  getDataKeys: (dataIds: string[]) => Promise<ServiceResponse<{ documentID: string, encryptedSymmetricKey: string }[]>>
  updateUser: (esk: ArrayBuffer, ssk: ArrayBuffer, salt: Uint8Array) => Promise<ServiceResponse<void>>
  giveAccess: (userId: string, docKeys: { documentID: string, encryptedSymmetricKey: string }[]) => Promise<ServiceResponse<void>>

  updateToken(token: string): void
  clearToken(): void
}

class BlindnetServiceHttp implements BlindnetService {
  apiUrl: string = undefined
  protocolVersion: string = undefined
  token: string = undefined

  constructor(token: string, apiUrl: string, protocolVersion: string) {
    this.token = token
    this.apiUrl = apiUrl
    this.protocolVersion = protocolVersion
  }

  registerUser: registerUserF =
    async (ePK, sPK, enc_eSK, enc_sSK, salt, signedToken, signedEncPK) => {
      const serverResp =
        await fetch(`${this.apiUrl}/api/v${this.protocolVersion}/users`, {
          method: 'POST',
          mode: 'cors',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.token}`
          },
          body: JSON.stringify({
            publicEncryptionKey: bin2b64str(ePK),
            publicSigningKey: bin2b64str(sPK),
            encryptedPrivateEncryptionKey: bin2b64str(enc_eSK),
            encryptedPrivateSigningKey: bin2b64str(enc_sSK),
            keyDerivationSalt: bin2b64str(salt),
            signedJwt: bin2b64str(signedToken),
            signedPublicEncryptionKey: bin2b64str(signedEncPK)
          })
        })

      return await handleResponse<void>(serverResp)(_ => undefined)
    }

  getUserData: () => Promise<ServiceResponse<GetUserResponse>> =
    async () => {
      const serverResp = await fetch(`${this.apiUrl}/api/v${this.protocolVersion}/keys/me`, {
        method: 'GET',
        mode: 'cors',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.token}`
        }
      })

      type ServerResponse = {
        publicEncryptionKey: string,
        encryptedPrivateEncryptionKey: string,
        publicSigningKey: string,
        encryptedPrivateSigningKey: string,
        keyDerivationSalt: string
      }

      function mapping(data: ServerResponse): GetUserResponse {
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

      return await handleResponse<ServerResponse>(serverResp, { type: 'UserNotFound' })(mapping)
    }

  getUsersPublicKey: (userId: string) => Promise<ServiceResponse<{ publicEncryptionKey: string, publicSigningKey: string }>> =
    async (userId) => {
      const serverResp = await fetch(`${this.apiUrl}/api/v${this.protocolVersion}/keys/${userId}`, {
        method: 'GET',
        mode: 'cors',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.token}`
        }
      })

      return await handleResponse<{ publicEncryptionKey: string, publicSigningKey: string }>(serverResp)(
        data => ({ ...data }))
    }

  getPublicKeys: (userIds: string[]) => Promise<ServiceResponse<{ publicEncryptionKey: string, userID: string }[]>> =
    async (userIds) => {
      const serverResp =
        await fetch(`${this.apiUrl}/api/v${this.protocolVersion}/keys`, {
          method: 'POST',
          mode: 'cors',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.token}`
          },
          body: JSON.stringify({
            userIds: userIds
          })
        })

      return await handleResponse<{ publicEncryptionKey: string, userID: string }[]>(serverResp)(data => data)
    }

  getGroupPublicKeys: (groupId: string) => Promise<ServiceResponse<{ publicEncryptionKey: string, userID: string }[]>> =
    async (groupId) => {
      const serverResp =
        await fetch(`${this.apiUrl}/api/v${this.protocolVersion}/keys`, {
          method: 'POST',
          mode: 'cors',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.token}`
          },
          body: JSON.stringify({
            groupId: groupId
          })
        })

      return await handleResponse<{ publicEncryptionKey: string, userID: string }[]>(serverResp)(data => data)
    }

  postEncryptedKeys: (encryptedKeys: { userID: string, encryptedSymmetricKey: string }[]) => Promise<ServiceResponse<string>> =
    async (encryptedKeys) => {
      const serverResp = await fetch(`${this.apiUrl}/api/v${this.protocolVersion}/documents`, {
        method: 'POST',
        mode: 'cors',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.token}`
        },
        body: JSON.stringify(encryptedKeys)
      })

      return await handleResponse<string>(serverResp)(data => data)
    }

  getDataKey: (dataId: string) => Promise<ServiceResponse<string>> =
    async (dataId) => {
      const serverResp = await fetch(`${this.apiUrl}/api/v${this.protocolVersion}/documents/keys/${dataId}`, {
        method: 'GET',
        mode: 'cors',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.token}`
        }
      })

      return await handleResponse<string>(serverResp)(data => data)
    }

  getAllDataKeys: () => Promise<ServiceResponse<{ documentID: string, encryptedSymmetricKey: string }[]>> =
    async () => {
      const serverResp = await fetch(`${this.apiUrl}/api/v${this.protocolVersion}/documents/keys`, {
        method: 'GET',
        mode: 'cors',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.token}`
        }
      })

      return await handleResponse<{ documentID: string, encryptedSymmetricKey: string }[]>(serverResp)(data => data)
    }

  getDataKeys: (dataIds: string[]) => Promise<ServiceResponse<{ documentID: string, encryptedSymmetricKey: string }[]>> =
    async (dataIds) => {
      const serverResp = await fetch(`${this.apiUrl}/api/v${this.protocolVersion}/documents/keys`, {
        method: 'POST',
        mode: 'cors',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.token}`
        },
        body: JSON.stringify({
          data_ids: dataIds
        })
      })

      return await handleResponse<{ documentID: string, encryptedSymmetricKey: string }[]>(serverResp)(data => data)
    }

  updateUser: (esk: ArrayBuffer, ssk: ArrayBuffer, salt: Uint8Array) => Promise<ServiceResponse<void>> =
    async (esk, ssk, salt) => {
      const serverResp = await fetch(`${this.apiUrl}/api/v${this.protocolVersion}/keys/me`, {
        method: 'PUT',
        mode: 'cors',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.token}`
        },
        body: JSON.stringify({
          encryptedPrivateEncryptionKey: bin2b64str(esk),
          encryptedPrivateSigningKey: bin2b64str(ssk),
          keyDerivationSalt: bin2b64str(salt)
        })
      })

      return await handleResponse<void>(serverResp)(_ => undefined)
    }

  giveAccess: (userId: string, docKeys: { documentID: string, encryptedSymmetricKey: string }[]) => Promise<ServiceResponse<void>> =
    async (userId, docKeys) => {
      const serverResp = await fetch(`${this.apiUrl}/api/v${this.protocolVersion}/documents/keys/user/${userId}`, {
        method: 'PUT',
        mode: 'cors',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.token}`
        },
        body: JSON.stringify(docKeys)
      })

      return await handleResponse<void>(serverResp)(_ => undefined)
    }

  updateToken: (token: string) => void = token => this.token = token

  clearToken: () => void = () => this.token = undefined
}

const handleResponse: <R>(resp: Response, notFoundData?: any) => <T>(f: (_: R) => T) => Promise<ServiceResponse<T>> =
  (resp, notFoundData) => async f => {
    switch (resp.status) {
      case 200: {
        const body = await resp.json()
        return { type: 'Success', data: f(body) }
      }
      case 401:
        return { type: 'AuthenticationNeeded' }
      // TODO: implement on server
      case 400: {
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
  GetUserResponse
}
