export declare function deriveIv(iv: Uint8Array, i: number): Promise<Uint8Array>;
export declare function deriveAESKey(password: string, salt: ArrayBuffer | string, extractable?: boolean): Promise<CryptoKey>;
export declare function deriveSecrets(seed: string, salt?: Uint8Array): Promise<{
    secret1: ArrayBuffer;
    secret2: ArrayBuffer;
}>;
export declare function generateRandomAESKey(): Promise<CryptoKey>;
export declare function generateRandomRSAKeyPair(): Promise<CryptoKeyPair>;
export declare function generateRandomSigningKeyPair(): Promise<{
    privateKey: Uint8Array;
    publicKey: Uint8Array;
}>;
export declare function sign(toSign: string | ArrayBuffer, secretKey: Uint8Array): Promise<ArrayBuffer>;
export declare function importPublicKey(publicKey: JsonWebKey): Promise<CryptoKey>;
export declare function exportPublicKey(publicKey: CryptoKey): Promise<JsonWebKey>;
export declare function wrapSecretKey(secretKey: CryptoKey, aesKey: CryptoKey, iv: ArrayBuffer): Promise<ArrayBuffer>;
export declare function unwrapSecretKey(wrappedSk: ArrayBuffer | string, aesKey: CryptoKey, iv: ArrayBuffer): Promise<CryptoKey>;
export declare function wrapAESKey(aesKey: CryptoKey, wrappingKey: CryptoKey): Promise<ArrayBuffer>;
export declare function unwrapAESKey(wrappedKey: ArrayBuffer | string, secretKey: CryptoKey): Promise<CryptoKey>;
export declare function encryptData(aesKey: CryptoKey, iv: ArrayBuffer, data: ArrayBuffer): Promise<ArrayBuffer>;
export declare function decryptData(aesKey: CryptoKey, iv: ArrayBuffer, encrypted: ArrayBuffer): Promise<ArrayBuffer>;
