declare type ServiceResponse<T> = {
    type: 'Success';
    data: T;
} | {
    type: 'AuthenticationNeeded';
} | {
    type: 'Failed';
};
declare type GetUserResponse = {
    type: 'UserFound';
    userData: {
        enc_PK: string;
        e_enc_SK: string;
        sign_PK: string;
        e_sign_SK: string;
        salt: string;
    };
} | {
    type: 'UserNotFound';
};
declare type registerUserF = (encryptionPublicKey: ArrayBuffer, signingPublicKey: ArrayBuffer, encryptedEncryptionSecretKey: ArrayBuffer, encryptedSigningSecretKey: ArrayBuffer, salt: Uint8Array, signedToken: ArrayBuffer, signedEncryptionPublicKey: ArrayBuffer) => Promise<ServiceResponse<void>>;
interface BlindnetService {
    token: string;
    protocolVersion: string;
    registerUser: registerUserF;
    getUserData: () => Promise<ServiceResponse<GetUserResponse>>;
    getUsersPublicKey: (userId: string) => Promise<ServiceResponse<{
        publicEncryptionKey: string;
        publicSigningKey: string;
    }>>;
    getPublicKeys: (userIds: string[]) => Promise<ServiceResponse<{
        publicEncryptionKey: string;
        userID: string;
    }[]>>;
    getGroupPublicKeys: (groupId: string) => Promise<ServiceResponse<{
        publicEncryptionKey: string;
        userID: string;
    }[]>>;
    postEncryptedKeys: (encryptedKeys: {
        userID: string;
        encryptedSymmetricKey: string;
    }[]) => Promise<ServiceResponse<string>>;
    postEncryptedKeysForData: (encryptedKeys: {
        userID: string;
        encryptedSymmetricKey: string;
    }[], documentID: string) => Promise<ServiceResponse<void>>;
    getDataKey: (dataId: string) => Promise<ServiceResponse<string>>;
    getAllDataKeys: () => Promise<ServiceResponse<{
        documentID: string;
        encryptedSymmetricKey: string;
    }[]>>;
    getDataKeys: (dataIds: string[]) => Promise<ServiceResponse<{
        documentID: string;
        encryptedSymmetricKey: string;
    }[]>>;
    updateUser: (esk: ArrayBuffer, ssk: ArrayBuffer, salt: Uint8Array) => Promise<ServiceResponse<void>>;
    giveAccess: (userId: string, docKeys: {
        documentID: string;
        encryptedSymmetricKey: string;
    }[]) => Promise<ServiceResponse<void>>;
    initializeUpload: () => Promise<ServiceResponse<{
        dataId: string;
    }>>;
    storeMetadata: (dataId: string, metadata: string) => Promise<ServiceResponse<void>>;
    getMetadata: (dataId: string) => Promise<ServiceResponse<string>>;
    getUploadBlockUrl: (dataId: string, chunkSize: number) => Promise<ServiceResponse<{
        blockId: string;
        date: string;
        authorization: string;
        url: string;
    }>>;
    finishUpload: (dataId: string, blockIds: string[]) => Promise<ServiceResponse<void>>;
    getDownloadLink: (dataId: string) => Promise<ServiceResponse<{
        date: string;
        authorization: string;
        url: string;
    }>>;
    updateToken(token: string): void;
    clearToken(): void;
}
declare class BlindnetServiceHttp implements BlindnetService {
    apiUrl: string;
    protocolVersion: string;
    token: string;
    constructor(token: string, apiUrl: string, protocolVersion: string);
    registerUser: registerUserF;
    getUserData: () => Promise<ServiceResponse<GetUserResponse>>;
    getUsersPublicKey: (userId: string) => Promise<ServiceResponse<{
        publicEncryptionKey: string;
        publicSigningKey: string;
    }>>;
    getPublicKeys: (userIds: string[]) => Promise<ServiceResponse<{
        publicEncryptionKey: string;
        userID: string;
    }[]>>;
    getGroupPublicKeys: (groupId: string) => Promise<ServiceResponse<{
        publicEncryptionKey: string;
        userID: string;
    }[]>>;
    postEncryptedKeys: (encryptedKeys: {
        userID: string;
        encryptedSymmetricKey: string;
    }[]) => Promise<ServiceResponse<string>>;
    postEncryptedKeysForData: (encryptedKeys: {
        userID: string;
        encryptedSymmetricKey: string;
    }[], documentID: string) => Promise<ServiceResponse<void>>;
    getDataKey: (dataId: string) => Promise<ServiceResponse<string>>;
    getAllDataKeys: () => Promise<ServiceResponse<{
        documentID: string;
        encryptedSymmetricKey: string;
    }[]>>;
    getDataKeys: (dataIds: string[]) => Promise<ServiceResponse<{
        documentID: string;
        encryptedSymmetricKey: string;
    }[]>>;
    getMetadata: (dataId: string) => Promise<ServiceResponse<string>>;
    updateUser: (esk: ArrayBuffer, ssk: ArrayBuffer, salt: Uint8Array) => Promise<ServiceResponse<void>>;
    giveAccess: (userId: string, docKeys: {
        documentID: string;
        encryptedSymmetricKey: string;
    }[]) => Promise<ServiceResponse<void>>;
    initializeUpload: () => Promise<ServiceResponse<{
        dataId: string;
    }>>;
    storeMetadata: (dataId: string, metadata: string) => Promise<ServiceResponse<void>>;
    getUploadBlockUrl: (dataId: string, chunkSize: number) => Promise<ServiceResponse<{
        blockId: string;
        date: string;
        authorization: string;
        url: string;
    }>>;
    finishUpload: (dataId: string, blockIds: string[]) => Promise<ServiceResponse<void>>;
    getDownloadLink: (dataId: string) => Promise<ServiceResponse<{
        date: string;
        authorization: string;
        url: string;
    }>>;
    updateToken: (token: string) => void;
    clearToken: () => void;
}
export { BlindnetService, BlindnetServiceHttp, ServiceResponse, GetUserResponse };
