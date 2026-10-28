// The interop assertion a real Conversations install makes before it will
// encrypt to us, reproduced with the peer's own library (libsignal_protocol_dart).
//
// libsignal's SessionBuilder does, verbatim:
//
//   if (preKey.getSignedPreKey() != null &&
//       !Curve.verifySignature(preKey.getIdentityKey().getPublicKey(),
//                              preKey.getSignedPreKey().serialize(),
//                              preKey.getSignedPreKeySignature()))
//   {
//     throw new InvalidKeyException("Invalid signature on device key!");
//   }
//
// The signed message is `signedPreKey.serialize()` (33 bytes, type byte first)
// — *not* the bare 32-byte key.

import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal_protocol_dart/libsignal_protocol_dart.dart';
import 'package:test/test.dart';

import 'package:omemo_dart/omemo_dart_axolotl.dart';

void main() {
  group('axolotl (Conversations) bundle signature', () {
    test('verifies exactly as SessionBuilder verifies it', () async {
      final device = await AxolotlDevice.generateNewDevice(
        'me@example.org',
        preKeyCount: 4,
      );
      final bundle = await device.toBundle();

      expect(
        bundle.identityKey.publicKey.serialize(),
        hasLength(33),
        reason: 'identity key serializes with the 0x05 type byte',
      );
      expect(bundle.identityKey.publicKey.serialize().first, Curve.djbType);
      expect(bundle.signedPreKeyPublic.serialize(), hasLength(33));
      expect(bundle.signedPreKeyPublic.serialize().first, Curve.djbType);
      expect(bundle.signedPreKeySignature, hasLength(64));

      expect(
        Curve.verifySignature(
          bundle.identityKey.publicKey,
          bundle.signedPreKeyPublic.serialize(),
          bundle.signedPreKeySignature,
        ),
        isTrue,
        reason: 'SessionBuilder must accept our signed prekey',
      );
    });

    test('the bare 32-byte key is not the signed message', () async {
      final device = await AxolotlDevice.generateNewDevice(
        'me@example.org',
        preKeyCount: 2,
      );
      final bundle = await device.toBundle();
      final bare = (bundle.signedPreKeyPublic as DjbECPublicKey).publicKey;

      expect(bare, hasLength(32));
      expect(
        Curve.verifySignature(
          bundle.identityKey.publicKey,
          bare,
          bundle.signedPreKeySignature,
        ),
        isFalse,
        reason: 'the signed message is the 33-byte serialization',
      );
    });

    test('every published key carries the type byte', () async {
      final device = await AxolotlDevice.generateNewDevice(
        'me@example.org',
        preKeyCount: 3,
      );
      final bundle = await device.toBundle();

      for (final entry in bundle.preKeysEncoded.entries) {
        final decoded = Curve.decodePoint(
          Uint8List.fromList(base64Decode(entry.value)),
          0,
        );
        expect(
          decoded.serialize().first,
          Curve.djbType,
          reason: 'prekey ${entry.key} must be serialized',
        );
        expect(decoded.serialize(), hasLength(33));
      }
    });
  });
}
