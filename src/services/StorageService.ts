import { ServiceResponse } from "./BlindnetService"

interface StorageService {
  uploadBlock: (url: string, authorization: string, date: string, body: ArrayBuffer) => Promise<ServiceResponse<void>>
  downloadBlob: (url: string, authorization: string, date: string) => Promise<ServiceResponse<ReadableStream<Uint8Array>>>
}

class AzureStorageService {

  constructor() { }

  uploadBlock: (url: string, authorization: string, date: string, body: ArrayBuffer) => Promise<ServiceResponse<void>> =
    async (url, authorization, date, body) => {

      const storageResp = await fetch(url, {
        method: 'PUT',
        headers: {
          'Authorization': authorization,
          'x-ms-date': date,
          'x-ms-blob-type': 'BlockBlob',
          'x-ms-version': '2021-04-10',
          "Content-Type": "application/octet-stream",
        },
        mode: 'cors',
        body: body
      })

      switch (storageResp.status) {
        case 201: {
          return { type: 'Success', data: undefined }
        }
        default:
          return { type: 'Failed' }
      }
    }

  downloadBlob: (url: string, authorization: string, date: string) => Promise<ServiceResponse<ReadableStream<Uint8Array>>> =
    async (url, authorization, date) => {

      const storageResp = await fetch(url, {
        method: 'GET',
        headers: {
          'Authorization': authorization,
          'x-ms-date': date,
          'x-ms-version': '2021-04-10',
        },
        mode: 'cors'
      })

      switch (storageResp.status) {
        case 200: {
          return { type: 'Success', data: storageResp.body }
        }
        default:
          return { type: 'Failed' }
      }
    }
}

export {
  StorageService,
  AzureStorageService
}
