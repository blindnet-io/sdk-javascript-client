import {
  arr2b64
} from './helper'

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
          PK: arr2b64(pk),
          eSK: arr2b64(esk),
          salt: arr2b64(salt)
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
        eSK: arr2b64(esk),
        salt: arr2b64(salt)
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

export {
  BlindnetService,
  BlindnetServiceHttp
}
