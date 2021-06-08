class AuthenticationError extends Error {
  code = 1
  constructor() {
    super('Authentication to blindnet failed. Please generate a valid token.');
    this.name = 'AuthenticationError'
  }
}

class UserNotInitializedError extends Error {
  code = 2
  constructor(message: string) {
    super(message);
    this.name = 'UserNotInitializedError'
  }
}

class PasswordError extends Error {
  code = 3
  constructor() {
    super('Wrong password provided.');
    this.name = 'PasswordError'
  }
}

class EncryptionError extends Error {
  code = 4
  constructor(message: string) {
    super(message);
    this.name = 'EncryptionError'
  }
}

class BlindnetServiceError extends Error {
  code = 5
  constructor(message: string) {
    super(message);
    this.name = 'BlindnetServiceError'
  }
}

class NotEncryptabeError extends Error {
  code = 6
  constructor() {
    super('No users to encrypt the data to');
    this.name = 'NotEncryptabeError'
  }
}

class NoAccessError extends Error {
  code = 7
  constructor(message: string) {
    super(message);
    this.name = 'NoAccessError'
  }
}

class UserNotFoundError extends Error {
  code = 8
  constructor(message: string) {
    super(message);
    this.name = 'UserNotFoundError'
  }
}

class BadFormatError extends Error {
  code = 9
  constructor(message: string) {
    super(message);
    this.name = 'BadFormatError'
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