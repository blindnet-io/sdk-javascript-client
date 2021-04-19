import {
  get,
  set,
  setMany,
  clear,
  createStore,
} from 'idb-keyval'

interface KeyStore {
  storeKey: (type: string, key: CryptoKey) => Promise<void>
  storeKeys: (privateKey: CryptoKey, publicKey: CryptoKey, aesKey: CryptoKey) => Promise<void>
  getKey: (type: string) => Promise<CryptoKey>
  clear: () => Promise<void>
}

class IndexedDbKeyStore implements KeyStore {
  store = createStore('blindnetKeys', 'keys')

  storeKey = (type, key) =>
    set(type, key, this.store)

  storeKeys = (privateKey, publicKey, aesKey) =>
    setMany([['private', privateKey], ['public', publicKey], ['derived', aesKey]], this.store)

  getKey = (type) =>
    get(type, this.store)

  clear = () => clear(this.store)
}

export {
  KeyStore,
  IndexedDbKeyStore
}
