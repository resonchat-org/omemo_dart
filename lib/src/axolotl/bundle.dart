import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal_protocol_dart/libsignal_protocol_dart.dart';
import 'package:meta/meta.dart';

import 'package:omemo_dart/src/axolotl/fingerprint.dart';

/// Remote device bundle for OMEMO 0.3.0 / Conversations PEP.
///
/// Key material is stored as base64 of libsignal `serialize()` output
/// (identity / prekeys include the `0x05` type byte).
@immutable
class AxolotlBundle {
  const AxolotlBundle({
    required this.jid,
    required this.deviceId,
    required this.signedPreKeyId,
    required this.signedPreKeyPublicEncoded,
    required this.signedPreKeySignatureEncoded,
    required this.identityKeyEncoded,
    required this.preKeysEncoded,
    this.registrationId,
  });

  final String jid;
  final int deviceId;
  final int signedPreKeyId;
  final String signedPreKeyPublicEncoded;
  final String signedPreKeySignatureEncoded;
  final String identityKeyEncoded;

  /// Map of preKeyId → base64(public key serialize()).
  final Map<int, String> preKeysEncoded;

  /// Optional remote registration id (same as device id in Conversations).
  final int? registrationId;

  IdentityKey get identityKey {
    final bytes = base64Decode(identityKeyEncoded);
    return IdentityKey.fromBytes(Uint8List.fromList(bytes), 0);
  }

  ECPublicKey get signedPreKeyPublic {
    final bytes = base64Decode(signedPreKeyPublicEncoded);
    return Curve.decodePoint(Uint8List.fromList(bytes), 0);
  }

  Uint8List get signedPreKeySignature =>
      Uint8List.fromList(base64Decode(signedPreKeySignatureEncoded));

  /// Pick one prekey (or null if the map is empty — Spekey-less bundle).
  MapEntry<int, ECPublicKey>? pickPreKey() {
    if (preKeysEncoded.isEmpty) return null;
    final id = preKeysEncoded.keys.first;
    final bytes = base64Decode(preKeysEncoded[id]!);
    return MapEntry(id, Curve.decodePoint(Uint8List.fromList(bytes), 0));
  }

  /// Build a libsignal [PreKeyBundle] using one of the published one-time keys.
  PreKeyBundle toPreKeyBundle() {
    final opk = pickPreKey();
    return PreKeyBundle(
      registrationId ?? deviceId,
      deviceId,
      opk?.key,
      opk?.value,
      signedPreKeyId,
      signedPreKeyPublic,
      signedPreKeySignature,
      identityKey,
    );
  }

  /// Whether a session can be opened with this device (signed-prekey verifies).
  ///
  /// Empty one-time pools are fine — Spekey-less sessions still work.
  bool get isUsable {
    try {
      final bundle = toPreKeyBundle();
      final spk = bundle.getSignedPreKey();
      if (spk == null) return false;
      return Curve.verifySignature(
        bundle.getIdentityKey().publicKey,
        spk.serialize(),
        bundle.getSignedPreKeySignature(),
      );
    } catch (_) {
      return false;
    }
  }

  String get fingerprint => axolotlFingerprint(identityKey);
}
