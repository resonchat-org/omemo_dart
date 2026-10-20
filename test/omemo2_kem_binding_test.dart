import 'dart:typed_data';

import 'package:omemo_dart/src/omemo2/bootstrap.dart';
import 'package:omemo_dart/src/omemo2/bundle_transcript.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(omemo2EnsureLibSignal);

  test('omemo2KemBinding known-answer (proto-XEP §4.9.1)', () {
    final binding = omemo2KemBinding(
      kemSignedPreKeyId: 1,
      kemSignedPreKeyPublic: Uint8List.fromList(List<int>.filled(4, 0xAA)),
      oneTime: [
        (id: 2, publicKey: Uint8List.fromList(List<int>.filled(3, 0xBB))),
        (id: 3, publicKey: Uint8List.fromList(List<int>.filled(5, 0xCC))),
      ],
    );
    expect(
      binding.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
      '7f93e76279a9e5c4dffe34e20c809fb2d1ef8dafaebf26742725aa4a1eba4d0f'
      'fac892689509fa655a04fb8a6d6c0beff91f757ab714b6cb8c8cd3303c8c98f2',
    );
  });

  test('empty one-time keys are stable', () {
    final a = omemo2KemBinding(
      kemSignedPreKeyId: 1,
      kemSignedPreKeyPublic: Uint8List.fromList([1, 2, 3]),
      oneTime: const [],
    );
    final b = omemo2KemBinding(
      kemSignedPreKeyId: 1,
      kemSignedPreKeyPublic: Uint8List.fromList([1, 2, 3]),
      oneTime: const [],
    );
    expect(a, b);
    expect(a.length, 64);
  });
}
