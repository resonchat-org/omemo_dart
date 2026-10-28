import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:omemo_dart/src/omemo2/kex_auth.dart';

void main() {
  test('omemo2KexAuthTranscript known-answer (proto-XEP §4.9.7)', () {
    // sender Alice@Example.com, sid = 42,
    // IK = 0x05 ‖ 0x11×32, PQ-IK = 0x22×2592,
    // kex: (Bob@Example.org, 12, 0x55×40),
    //      (alice@example.com, 7, 0x66×50),
    //      (alice@example.com, 3, 0x77×30).
    final digest = omemo2KexAuthTranscriptDigestHex(
      senderBareJid: 'Alice@Example.com',
      sid: 42,
      identityKey: Uint8List.fromList([0x05, ...List<int>.filled(32, 0x11)]),
      pqIdentityKey: Uint8List.fromList(List<int>.filled(2592, 0x22)),
      entries: [
        Omemo2KexAuthEntry(
          jid: 'Bob@Example.org',
          rid: 12,
          keyBytes: Uint8List.fromList(List<int>.filled(40, 0x55)),
        ),
        Omemo2KexAuthEntry(
          jid: 'alice@example.com',
          rid: 7,
          keyBytes: Uint8List.fromList(List<int>.filled(50, 0x66)),
        ),
        Omemo2KexAuthEntry(
          jid: 'alice@example.com',
          rid: 3,
          keyBytes: Uint8List.fromList(List<int>.filled(30, 0x77)),
        ),
      ],
    );
    expect(
      digest,
      '281cdeaf99a47eadaa3d51a49ae09c743afc7478b943d9995f7db71ef0533679'
      '988c4923ebf5ed8c1e1407c199fe6a0dee8439c6f2385cbb527b924bb9859248',
    );
  });
}
