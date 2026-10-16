import 'dart:convert';
import 'dart:typed_data';

import 'package:omemo_dart/omemo_dart_omemo2.dart';
import 'package:test/test.dart';

void main() {
  test('seal/open round-trip with commit', () async {
    final mk = Uint8List.fromList(List<int>.generate(32, (i) => i + 1));
    final binding = omemo2ContextBinding(
      senderBareJid: 'alice@example.org',
      recipientBareJid: 'bob@example.org',
      sourceDeviceId: 7,
    );
    final sealed = await omemo2SealPayload(
      messageKey: mk,
      plaintext: utf8.encode('payload hello'),
      binding: binding,
    );
    expect(sealed.commit.length, 64);

    final opened = await omemo2OpenPayload(
      messageKey: mk,
      ciphertextWithMac: sealed.ciphertextWithMac,
      commit: sealed.commit,
      binding: binding,
    );
    expect(utf8.decode(opened), 'payload hello');
  });

  test('tampered commit is refused', () async {
    final mk = Uint8List(32);
    final binding = omemo2ContextBinding(
      senderBareJid: 'a@x',
      recipientBareJid: 'b@y',
      sourceDeviceId: 1,
    );
    final sealed = await omemo2SealPayload(
      messageKey: mk,
      plaintext: utf8.encode('x'),
      binding: binding,
    );
    final badCommit = Uint8List.fromList(sealed.commit);
    badCommit[0] ^= 0xff;

    expect(
      () => omemo2OpenPayload(
        messageKey: mk,
        ciphertextWithMac: sealed.ciphertextWithMac,
        commit: badCommit,
        binding: binding,
      ),
      throwsStateError,
    );
  });
}
