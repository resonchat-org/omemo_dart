import 'dart:typed_data';

import 'package:pointycastle/digests/sha3.dart';
import 'package:test/test.dart';

import 'package:omemo_dart/src/omemo2/bootstrap.dart';
import 'package:omemo_dart/src/omemo2/bundle_transcript.dart';

void main() {
  setUpAll(omemo2EnsureLibSignal);

  test('omemo2BundleTranscript known-answer (proto-XEP §4.9.1 v4)', () {
    // IK = 0x05 ‖ 0x11×32, PQ-IK = 0x22×2592, signedPreKeyId = 7,
    // SPK = 0x05 ‖ 0x33×32, KEM-BINDING = 0x44×64.
    // Spec asserts SHA3-512 of the transcript bytes (not the raw transcript).
    final transcript = omemo2BundleTranscript(
      identityKey: Uint8List.fromList([0x05, ...List<int>.filled(32, 0x11)]),
      pqIdentityKey: Uint8List.fromList(List<int>.filled(2592, 0x22)),
      signedPreKeyId: 7,
      signedPreKeyPublic: Uint8List.fromList([
        0x05,
        ...List<int>.filled(32, 0x33),
      ]),
      kemBinding: Uint8List.fromList(List<int>.filled(64, 0x44)),
    );
    final digest = SHA3Digest(512);
    digest.update(transcript, 0, transcript.length);
    final out = Uint8List(64);
    digest.doFinal(out, 0);
    expect(
      out.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
      '51006cbeb032541274a0222b2b2e6ef68250803ccd9f8921ffcd8a93b4be7028'
      'dec4c46f0dfb1d50a3add5593871157dd0c1ce958d5aa35f320ffbdafcfd621a',
    );
  });
}
