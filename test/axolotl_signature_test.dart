// XEdDSA and the usable-bundle gate for classic OMEMO / Conversations.
//
// OMEMO 0.3 makes every session depend on the peer's signature over its signed
// prekey. A signed prekey we publish and cannot verify back would mean no
// Conversations client could start a session with us.

import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal_protocol_dart/libsignal_protocol_dart.dart';
import 'package:omemo_dart/omemo_dart_axolotl.dart';
import 'package:test/test.dart';

void main() {
  test('a signature we make over our own signed prekey verifies', () {
    final identity = generateIdentityKeyPair();
    final signed = generateSignedPreKey(identity, 1234);

    expect(
      Curve.verifySignature(
        identity.getPublicKey().publicKey,
        signed.getKeyPair().publicKey.serialize(),
        signed.signature,
      ),
      isTrue,
      reason: 'our own published bundle must pass the check every client runs',
    );
  });

  test('the low-level primitive round-trips', () {
    final pair = Curve.generateKeyPair();
    final message = Uint8List.fromList(List<int>.filled(33, 0x05));

    final signature = Curve.calculateSignature(pair.privateKey, message);

    expect(signature.length, 64);
    expect(Curve.verifySignature(pair.publicKey, message, signature), isTrue);
  });

  test(
    'a bundle we publish ourselves is usable, and one bit off is not',
    () async {
      final device = await AxolotlDevice.generateNewDevice(
        'peer@example.org',
        preKeyCount: 4,
      );
      final bundle = await device.toBundle();
      expect(bundle.isUsable, isTrue);

      final signature = base64Decode(bundle.signedPreKeySignatureEncoded);
      signature[0] ^= 0x01;
      expect(
        AxolotlBundle(
          jid: bundle.jid,
          deviceId: bundle.deviceId,
          signedPreKeyId: bundle.signedPreKeyId,
          signedPreKeyPublicEncoded: bundle.signedPreKeyPublicEncoded,
          signedPreKeySignatureEncoded: base64Encode(signature),
          identityKeyEncoded: bundle.identityKeyEncoded,
          preKeysEncoded: bundle.preKeysEncoded,
        ).isUsable,
        isFalse,
      );
    },
  );

  test(
    'a device that has handed out all of its prekeys is still usable',
    () async {
      final device = await AxolotlDevice.generateNewDevice(
        'peer@example.org',
        preKeyCount: 4,
      );
      final bundle = await device.toBundle();
      expect(
        AxolotlBundle(
          jid: bundle.jid,
          deviceId: bundle.deviceId,
          signedPreKeyId: bundle.signedPreKeyId,
          signedPreKeyPublicEncoded: bundle.signedPreKeyPublicEncoded,
          signedPreKeySignatureEncoded: bundle.signedPreKeySignatureEncoded,
          identityKeyEncoded: bundle.identityKeyEncoded,
          preKeysEncoded: const {},
        ).isUsable,
        isTrue,
      );
    },
  );
}
