import 'dart:typed_data';

import 'package:omemo_dart/src/omemo2/constants.dart';
import 'package:omemo_dart/src/omemo2/errors.dart';

/// Encode a raw ML-KEM-1024 public key for the wire (`0x0A ‖ pk`).
Uint8List serializeMlKem1024PublicKey(List<int> rawPublicKey) {
  if (rawPublicKey.length != omemo2MlKemPublicKeyLength) {
    throw const Omemo2KemException(
      'ML-KEM-1024 public key must be $omemo2MlKemPublicKeyLength bytes',
    );
  }
  return Uint8List.fromList([omemo2MlKem1024Tag, ...rawPublicKey]);
}

/// Decode a wire ML-KEM public key. Refuses Round-3 Kyber (`0x08`).
Uint8List parseMlKem1024PublicKey(List<int> serialized) {
  if (serialized.isEmpty) {
    throw const Omemo2KemException('empty KEM public key');
  }
  final tag = serialized[0];
  if (tag == omemo2Kyber1024Round3Tag) {
    throw const Omemo2KemException(
      'Round-3 Kyber-1024 keys are refused (tag 0x08)',
    );
  }
  if (tag != omemo2MlKem1024Tag) {
    throw Omemo2KemException(
      'unsupported KEM public key tag 0x${tag.toRadixString(16)}',
    );
  }
  if (serialized.length != 1 + omemo2MlKemPublicKeyLength) {
    throw Omemo2KemException(
      'ML-KEM-1024 public key must be ${1 + omemo2MlKemPublicKeyLength} bytes, '
      'got ${serialized.length}',
    );
  }
  return Uint8List.fromList(serialized.sublist(1));
}
