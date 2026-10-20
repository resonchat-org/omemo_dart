import 'dart:convert';
import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:pointycastle/digests/sha3.dart';

/// Domain-separation label used by monocles
/// `CryptoHelper.hybridOmemo2Fingerprint`.
final Uint8List kHybridOmemo2FpLabel = Uint8List.fromList(
  ascii.encode('monocles:omemo2:ik:v2'),
);

/// monocles `CryptoHelper.hybridOmemo2Fingerprint`: SHA3-512 over
/// `monocles:omemo2:ik:v2` ‖ len32(classical IK) ‖ classical IK ‖
/// len32(pq IK) ‖ pq IK. Returns lowercase hex (128 chars).
///
/// Pair of `axolotlFingerprint`: both identity fingerprints live in
/// omemo_dart. monocles hashes with BouncyCastle `SHA3Digest`, not libsignal;
/// this uses the same algorithm via pointycastle so the app does not have to
/// depend on `pqcrypto` for the digest.
String hybridOmemo2Fingerprint(Uint8List identityKey, Uint8List pqIdentityKey) {
  final digest = SHA3Digest(512);
  digest.update(kHybridOmemo2FpLabel, 0, kHybridOmemo2FpLabel.length);
  _updateLengthPrefixed(digest, identityKey);
  _updateLengthPrefixed(digest, pqIdentityKey);
  final out = Uint8List(64);
  digest.doFinal(out, 0);
  return HEX.encode(out);
}

void _updateLengthPrefixed(SHA3Digest digest, Uint8List value) {
  final len = ByteData(4)..setInt32(0, value.length, Endian.big);
  final bytes = len.buffer.asUint8List();
  digest.update(bytes, 0, bytes.length);
  if (value.isNotEmpty) digest.update(value, 0, value.length);
}
