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
  UserNotInitializedError,
  EncryptionError,
  BlindnetServiceError,
  PassphraseError
}