class AuthenticationError extends Error {
  code = 'blindnet.authentication'
  constructor() {
    super('Authentication to blindnet failed. Please generate a valid token.')
    this.name = 'AuthenticationError'

    Object.setPrototypeOf(this, new.target.prototype)
  }
}

class UserNotInitializedError extends Error {
  code = 'blindnet.user_not_initialized'
  constructor(message: string) {
    super(message)
    this.name = 'UserNotInitializedError'

    Object.setPrototypeOf(this, new.target.prototype)
  }
}

class SecretError extends Error {
  code = 'blindnet.secret'
  constructor() {
    super('Wrong secret provided.')
    this.name = 'SecretError'

    Object.setPrototypeOf(this, new.target.prototype)
  }
}

class BadFormatError extends Error {
  code = 'blindnet.data_format'
  constructor(message: string) {
    super(message)
    this.name = 'BadFormatError'

    Object.setPrototypeOf(this, new.target.prototype)
  }
}

class EncryptionError extends Error {
  code = 'blindnet.encryption'
  constructor(message: string) {
    super(message)
    this.name = 'EncryptionError'

    Object.setPrototypeOf(this, new.target.prototype)
  }
}

class BlindnetServiceError extends Error {
  code = 'blindnet.service'
  constructor(message: string) {
    super(message)
    this.name = 'BlindnetServiceError'

    Object.setPrototypeOf(this, new.target.prototype)
  }
}

class NotEncryptabeError extends Error {
  code = 'blindnet.not_encryptable'
  constructor(message: string) {
    super(message)
    this.name = 'NotEncryptabeError'

    Object.setPrototypeOf(this, new.target.prototype)
  }
}

class NoAccessError extends Error {
  code = 7
  constructor(message: string) {
    super(message)
    this.name = 'NoAccessError'

    Object.setPrototypeOf(this, new.target.prototype)
  }
}

class UserNotFoundError extends Error {
  code = 8
  constructor(message: string) {
    super(message)
    this.name = 'UserNotFoundError'

    Object.setPrototypeOf(this, new.target.prototype)
  }
}

export {
  AuthenticationError,
  UserNotInitializedError,
  SecretError,
  EncryptionError,
  BlindnetServiceError,
  NotEncryptabeError,
  NoAccessError,
  UserNotFoundError,
  BadFormatError
}