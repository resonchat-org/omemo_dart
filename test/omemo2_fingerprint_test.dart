import 'dart:convert';
import 'dart:typed_data';

import 'package:omemo_dart/omemo_dart_omemo2.dart';
import 'package:test/test.dart';

void main() {
  group('hybridOmemo2Fingerprint', () {
    test('matches monocles CryptoHelper known-answer vector', () {
      final ik = Uint8List(33);
      ik[0] = 0x05;
      for (var i = 1; i < 33; i++) {
        ik[i] = 0x11;
      }
      final pq = Uint8List(2592);
      for (var i = 0; i < pq.length; i++) {
        pq[i] = 0x22;
      }
      const want =
          '6b6ea370b7cbc0078f992487b235ab384a7f272b232e508a2d27da9b42f1def7'
          'f2def0daffbdfd91a33065c1e383473a1eacce6e5709833d286c5e399e19c77a';
      expect(hybridOmemo2Fingerprint(ik, pq), want);
    });

    test('is 128 lowercase hex and domain-separated', () {
      final ik = Uint8List.fromList(List<int>.generate(33, (i) => i));
      final pq = Uint8List.fromList(List<int>.generate(64, (i) => 255 - i));
      final a = hybridOmemo2Fingerprint(ik, pq);
      final b = hybridOmemo2Fingerprint(ik, pq);
      expect(a, b);
      expect(a.length, 128);
      expect(RegExp(r'^[0-9a-f]+$').hasMatch(a), isTrue);

      final pq2 = Uint8List.fromList(pq);
      pq2[0] ^= 0xff;
      expect(hybridOmemo2Fingerprint(ik, pq2), isNot(a));

      expect(ascii.decode(kHybridOmemo2FpLabel), 'monocles:omemo2:ik:v2');
    });

    test('length-prefix changes the digest', () {
      final ik = Uint8List.fromList([1, 2, 3]);
      final pq = Uint8List.fromList([4, 5, 6, 7]);
      final base = hybridOmemo2Fingerprint(ik, pq);
      expect(hybridOmemo2Fingerprint(ik, Uint8List(0)), isNot(base));
    });
  });
}
