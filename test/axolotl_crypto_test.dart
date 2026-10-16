import 'dart:convert';

import 'package:omemo_dart/omemo_dart_axolotl.dart';
import 'package:test/test.dart';

void main() {
  test('AES-128-GCM auth-tag-in-key roundtrip', () async {
    final plain = utf8.encode('hello axolotl');
    final enc = await axolotlEncryptPayload(plain);

    expect(enc.iv.length, axolotlIvLength);
    expect(enc.keyPlusTag.length, axolotlAesKeyLength + axolotlGcmTagLength);

    final dec = await axolotlDecryptPayload(
      ciphertextWithoutTag: enc.ciphertextWithoutTag,
      keyPlusTag: enc.keyPlusTag,
      iv: enc.iv,
    );
    expect(utf8.decode(dec), 'hello axolotl');
  });

  test('rejects short key material in auth-tag-in-key mode', () async {
    final enc = await axolotlEncryptPayload(utf8.encode('x'));
    expect(
      () => axolotlDecryptPayload(
        ciphertextWithoutTag: enc.ciphertextWithoutTag,
        keyPlusTag: enc.keyPlusTag.sublist(0, 16),
        iv: enc.iv,
      ),
      throwsArgumentError,
    );
  });
}
