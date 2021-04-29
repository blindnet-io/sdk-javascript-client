import {
  get,
  set,
  setMany,
  clear,
  createStore,
} from 'idb-keyval'

interface KeyStore {
  storeKey: (type: string, key: CryptoKey) => Promise<void>
  storeKeys: (privateEnc: CryptoKey, publicEnc: CryptoKey, privateSign: CryptoKey, publicSign: CryptoKey, aes: CryptoKey) => Promise<void>
  getKey: (type: string) => Promise<CryptoKey>
  clear: () => Promise<void>
}

class IndexedDbKeyStore implements KeyStore {
  store = createStore('blindnetKeys', 'keys')

  storeKey = (type, key) =>
    set(type, key, this.store)

  storeKeys = (privateEnc, publicEnc, privateSign, publicSign, aes) =>
    setMany([['private_enc', privateEnc], ['public_enc', publicEnc], ['private_sign', privateEnc], ['public_sign', publicEnc], ['derived', aes]], this.store)

  getKey = (type) =>
    get(type, this.store)

  clear = () => clear(this.store)
}

export {
  KeyStore,
  IndexedDbKeyStore
}
