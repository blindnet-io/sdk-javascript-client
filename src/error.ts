class AuthenticationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthenticationError"
  }
}

class UserNotInitializedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UserNotInitializedError"
  }
}

class EncryptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EncryptionError"
  }
}

class BlindnetServiceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BlindnetServiceError"
  }
}

class PassphraseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PassphraseError"
  }
}

export {
  AuthenticationError,
  UserNotInitializedError,
  EncryptionError,
  BlindnetServiceError,
  PassphraseError
}