class AuthenticationError extends Error {
  code = 1
  constructor() {
    super('Authentication failed. Please generate a valid JWT.');
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

class PassphraseError extends Error {
  code = 3
  constructor() {
    super('Wrong passphrase provided.');
    this.name = 'PassphraseError'
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

class NoRegisteredUsersError extends Error {
  code = 6
  constructor() {
    super('No users to encrypt the data to');
    this.name = 'NoRegisteredUsersError'
  }
}

class NoAccessError extends Error {
  code = 7
  constructor(message: string) {
    super(message);
    this.name = 'NoRegisteredUsersError'
  }
}

class UserNotFoundError extends Error {
  code = 8
  constructor(message: string) {
    super(message);
    this.name = 'UserNotFoundError'
  }
}

export {
  AuthenticationError,
  UserNotInitializedError,
  PassphraseError,
  EncryptionError,
  BlindnetServiceError,
  NoRegisteredUsersError,
  NoAccessError,
  UserNotFoundError
}