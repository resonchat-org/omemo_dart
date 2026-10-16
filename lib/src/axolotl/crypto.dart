import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:omemo_dart/src/axolotl/constants.dart';
import 'package:omemo_dart/src/common/helpers.dart';

/// Result of encrypting a UTF-8 body with AES-128-GCM under the Conversations
/// "auth tag in key" convention.
class AxolotlPayloadEncryption {
  const AxolotlPayloadEncryption({
    required this.ciphertextWithoutTag,
    required this.keyPlusTag,
    required this.iv,
  });

  /// Ciphertext with the 16-byte GCM tag removed (goes into `<payload>`).
  final List<int> ciphertextWithoutTag;

  /// `AES-key(16) ‖ GCM-tag(16)` — what each `<key>` encrypts with Signal.
  final List<int> keyPlusTag;

  /// 12-byte IV for `<iv>`.
  final List<int> iv;
}

/// Encrypt [plaintext] with a fresh AES-128 key and 12-byte IV.
Future<AxolotlPayloadEncryption> axolotlEncryptPayload(
  List<int> plaintext,
) async {
  final key = generateRandomBytes(axolotlAesKeyLength);
  final iv = generateRandomBytes(axolotlIvLength);
  final algorithm = AesGcm.with128bits();
  final box = await algorithm.encrypt(
    plaintext,
    secretKey: SecretKey(key),
    nonce: iv,
  );

  final ciphertext = box.cipherText;
  final tag = box.mac.bytes;
  if (tag.length != axolotlGcmTagLength) {
    throw StateError('Unexpected GCM tag length ${tag.length}');
  }

  if (axolotlPutAuthTagIntoKey) {
    return AxolotlPayloadEncryption(
      ciphertextWithoutTag: ciphertext,
      keyPlusTag: [...key, ...tag],
      iv: iv,
    );
  }

  return AxolotlPayloadEncryption(
    ciphertextWithoutTag: [...ciphertext, ...tag],
    keyPlusTag: key,
    iv: iv,
  );
}

/// Decrypt [ciphertextWithoutTag] using material recovered from a Signal
/// `<key>` ([keyPlusTag]) and the wire [iv].
Future<List<int>> axolotlDecryptPayload({
  required List<int> ciphertextWithoutTag,
  required List<int> keyPlusTag,
  required List<int> iv,
}) async {
  if (keyPlusTag.length < axolotlAesKeyLength) {
    throw ArgumentError('key material too short: ${keyPlusTag.length}');
  }

  List<int> key;
  List<int> ciphertext;
  List<int> tag;

  if (axolotlPutAuthTagIntoKey) {
    if (keyPlusTag.length < axolotlAesKeyLength + axolotlGcmTagLength) {
      // Conversations rejects this as OutdatedSenderException.
      throw ArgumentError(
        'key+tag too short for auth-tag-in-key mode: ${keyPlusTag.length}',
      );
    }
    key = keyPlusTag.sublist(0, axolotlAesKeyLength);
    tag = keyPlusTag.sublist(
      axolotlAesKeyLength,
      axolotlAesKeyLength + axolotlGcmTagLength,
    );
    ciphertext = ciphertextWithoutTag;
  } else {
    key = keyPlusTag.sublist(0, axolotlAesKeyLength);
    if (ciphertextWithoutTag.length < axolotlGcmTagLength) {
      throw ArgumentError('ciphertext too short');
    }
    ciphertext = ciphertextWithoutTag.sublist(
      0,
      ciphertextWithoutTag.length - axolotlGcmTagLength,
    );
    tag = ciphertextWithoutTag.sublist(
      ciphertextWithoutTag.length - axolotlGcmTagLength,
    );
  }

  final algorithm = AesGcm.with128bits();
  return algorithm.decrypt(
    SecretBox(ciphertext, nonce: iv, mac: Mac(tag)),
    secretKey: SecretKey(key),
  );
}

/// Move auth tag from ciphertext end onto the key (Smack/Conversations helper).
void moveAuthTagOntoKey({
  required List<int> messageKey,
  required List<int> ciphertextWithTag,
  required List<int> outKeyPlusTag,
  required List<int> outCiphertextWithoutTag,
}) {
  assert(messageKey.length == axolotlAesKeyLength, 'AES-128 key');
  assert(
    ciphertextWithTag.length >= axolotlGcmTagLength,
    'ciphertext must include tag',
  );
  final bodyLen = ciphertextWithTag.length - axolotlGcmTagLength;
  for (var i = 0; i < axolotlAesKeyLength; i++) {
    outKeyPlusTag[i] = messageKey[i];
  }
  for (var i = 0; i < axolotlGcmTagLength; i++) {
    outKeyPlusTag[axolotlAesKeyLength + i] = ciphertextWithTag[bodyLen + i];
  }
  for (var i = 0; i < bodyLen; i++) {
    outCiphertextWithoutTag[i] = ciphertextWithTag[i];
  }
}

/// Convenience: secure random as [Uint8List].
Uint8List axolotlRandomBytes(int length) =>
    Uint8List.fromList(generateRandomBytes(length));
