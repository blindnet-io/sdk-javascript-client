class AuthenticationError extends Error {
  code = 1
  constructor() {
    super('Authentication to blindnet failed. Please generate a valid token.')
    this.name = 'AuthenticationError'

    Object.setPrototypeOf(this, new.target.prototype)
  }
}

class UserNotInitializedError extends Error {
  code = 2
  constructor(message: string) {
    super(message)
    this.name = 'UserNotInitializedError'

    Object.setPrototypeOf(this, new.target.prototype)
  }
}

class PasswordError extends Error {
  code = 3
  constructor() {
    super('Wrong password provided.')
    this.name = 'PasswordError'

    Object.setPrototypeOf(this, new.target.prototype)
  }
}

class EncryptionError extends Error {
  code = 4
  constructor(message: string) {
    super(message)
    this.name = 'EncryptionError'

    Object.setPrototypeOf(this, new.target.prototype)
  }
}

class BlindnetServiceError extends Error {
  code = 5
  constructor(message: string) {
    super(message)
    this.name = 'BlindnetServiceError'

    Object.setPrototypeOf(this, new.target.prototype)
  }
}

class NotEncryptabeError extends Error {
  code = 6
  constructor() {
    super('No users to encrypt the data to')
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

class BadFormatError extends Error {
  code = 9
  constructor(message: string) {
    super(message)
    this.name = 'BadFormatError'

    Object.setPrototypeOf(this, new.target.prototype)
  }
}

export {
  AuthenticationError,
  UserNotInitializedError,
  PasswordError,
  EncryptionError,
  BlindnetServiceError,
  NotEncryptabeError,
  NoAccessError,
  UserNotFoundError,
  BadFormatError
}