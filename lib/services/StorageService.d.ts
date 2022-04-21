import { ServiceResponse } from "./BlindnetService";
interface StorageService {
    uploadBlock: (url: string, authorization: string, date: string, body: ArrayBuffer) => Promise<ServiceResponse<void>>;
    downloadBlob: (url: string, authorization: string, date: string) => Promise<ServiceResponse<ReadableStream<Uint8Array>>>;
}
declare class AzureStorageService {
    constructor();
    uploadBlock: (url: string, authorization: string, date: string, body: ArrayBuffer) => Promise<ServiceResponse<void>>;
    downloadBlob: (url: string, authorization: string, date: string) => Promise<ServiceResponse<ReadableStream<Uint8Array>>>;
}
export { StorageService, AzureStorageService };
