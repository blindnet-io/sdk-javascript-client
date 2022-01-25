import * as idb from 'idb-keyval'

type Keys = {
  eSK: CryptoKey,
  ePK: CryptoKey,
  sSK: Uint8Array,
  sPK: Uint8Array,
  aes: CryptoKey
}

interface KeyStore {
  storeKey: (type: string, key: CryptoKey) => Promise<void>
  storeKeys: (eSK: CryptoKey, ePK: CryptoKey, sSK: Uint8Array, sPK: Uint8Array, aes: CryptoKey) => Promise<void>
  getKey: (type: 'private_enc' | 'public_enc' | 'derived') => Promise<CryptoKey>
  getSignKey: (type: 'private_sign' | 'public_sign') => Promise<Uint8Array>
  getKeys: () => Promise<Keys>
  clear: () => Promise<void>
}

class IndexedDbKeyStore implements KeyStore {
  keys = ['private_enc', 'public_enc', 'private_sign', 'public_sign', 'derived']
  keyLabels = ['eSK', 'ePK', 'sSK', 'sPK', 'aes']

  private store: idb.UseStore

  constructor(storeName: string = 'keys') {
    this.store = idb.createStore('blindnet', storeName)
  }

  storeKey = (type, key) =>
    idb.set(type, key, this.store)

  storeKeys = (eSK, ePK, sSK, sPK, aes) =>
    idb.setMany([['private_enc', eSK], ['public_enc', ePK], ['private_sign', sSK], ['public_sign', sPK], ['derived', aes]], this.store)

  getKey = (type) =>
    idb.get(type, this.store)

  getSignKey = (type) =>
    idb.get(type, this.store)

  getKeys = () =>
    idb.getMany(this.keys, this.store)
      .then(res => res.reduce((acc, cur, i) => ({ ...acc, [this.keyLabels[i]]: cur }), {}))

  clear = () => idb.clear(this.store)
}

export {
  KeyStore,
  IndexedDbKeyStore
}
