declare type Keys = {
    eSK: CryptoKey;
    ePK: CryptoKey;
    sSK: Uint8Array;
    sPK: Uint8Array;
    aes: CryptoKey;
};
interface KeyStore {
    storeKey: (type: string, key: CryptoKey) => Promise<void>;
    storeKeys: (eSK: CryptoKey, ePK: CryptoKey, sSK: Uint8Array, sPK: Uint8Array, aes: CryptoKey) => Promise<void>;
    getKey: (type: 'private_enc' | 'public_enc' | 'derived') => Promise<CryptoKey>;
    getSignKey: (type: 'private_sign' | 'public_sign') => Promise<Uint8Array>;
    getKeys: () => Promise<Keys>;
    clear: () => Promise<void>;
}
declare class IndexedDbKeyStore implements KeyStore {
    keys: string[];
    keyLabels: string[];
    private store;
    constructor(dbName?: string, storeName?: string);
    storeKey: (type: any, key: any) => Promise<void>;
    storeKeys: (eSK: any, ePK: any, sSK: any, sPK: any, aes: any) => Promise<void>;
    getKey: (type: any) => Promise<any>;
    getSignKey: (type: any) => Promise<any>;
    getKeys: () => Promise<any>;
    clear: () => Promise<void>;
}
export { KeyStore, IndexedDbKeyStore };
