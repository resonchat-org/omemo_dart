/// Base error type shared by Axolotl and OMEMO2 managers.
abstract class OmemoError {
  const OmemoError();
}

/// Encryption failed for a specific remote device (or the whole JID).
class EncryptToJidError extends OmemoError {
  EncryptToJidError(this.device, this.error);

  /// The device the error occurred with, or null when JID-level.
  final int? device;

  /// The underlying error.
  final OmemoError error;
}

/// Message was not encrypted for our device.
class NotEncryptedForDeviceError extends OmemoError {
  const NotEncryptedForDeviceError();
}

/// No remote key material / bundle available.
class NoKeyMaterialAvailableError extends OmemoError {
  const NoKeyMaterialAvailableError();
}

/// No session with the sending device.
class NoSessionWithDeviceError extends OmemoError {
  const NoSessionWithDeviceError();
}

/// Ciphertext could not be opened (MAC / format / crypto failure).
class MalformedCiphertextError extends OmemoError {
  MalformedCiphertextError(this.ex);

  final Object ex;
}

/// Empty or unusable `<key />` content.
class MalformedEncryptedKeyError extends OmemoError {
  const MalformedEncryptedKeyError();
}
