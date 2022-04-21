import { KeyStore } from '../src/storage/KeyStore'

class TestKeyStore implements KeyStore {
  store = {}

  storeKey = (type, key) => {
    this.store[type] = key
    return Promise.resolve()
  }

  storeKeys = (privateEnc, publicEnc, privateSign, publicSign, aes) => {
    this.store['private_enc'] = privateEnc
    this.store['public_enc'] = publicEnc
    this.store['private_sign'] = privateSign
    this.store['public_sign'] = publicSign
    this.store['derived'] = aes
    return Promise.resolve()
  }

  getKey = (type) =>
    Promise.resolve(this.store[type])

  getSignKey = (type) =>
    Promise.resolve(this.store[type])

  getKeys = () =>
    Promise.resolve({
      eSK: this.store['private_enc'],
      ePK: this.store['public_enc'],
      sSK: this.store['private_sign'],
      sPK: this.store['public_sign'],
      aes: this.store['derived']
    })

  clear = () => {
    this.store = {}
    return Promise.resolve()
  }
}

export {
  TestKeyStore,
}