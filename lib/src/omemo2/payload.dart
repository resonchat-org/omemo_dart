import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:omemo_dart/src/omemo2/kmac.dart';

/// KMAC customization for payload key/IV derivation (monocles proto-XEP §5.4).
const String omemo2PayloadKmacLabel = 'monocles:omemo2:payload:v3';

/// KMAC customization for key commitment (proto-XEP §5.5).
const String omemo2CommitKmacLabel = 'monocles:omemo2:key-commitment:v3';

/// Context binding for OMEMO2 payload AEAD (sender ‖ recipient ‖ device).
Uint8List omemo2ContextBinding({
  required String senderBareJid,
  required String recipientBareJid,
  required int sourceDeviceId,
}) {
  final buf = BytesBuilder(copy: false);
  void lp(List<int> b) {
    final len = ByteData(4)..setUint32(0, b.length);
    buf
      ..add(len.buffer.asUint8List())
      ..add(b);
  }

  lp(utf8.encode(senderBareJid));
  lp(utf8.encode(recipientBareJid));
  final id = ByteData(4)..setUint32(0, sourceDeviceId);
  lp(id.buffer.asUint8List());
  return buf.toBytes();
}

class Omemo2PayloadSeal {
  const Omemo2PayloadSeal({
    required this.ciphertextWithMac,
    required this.commit,
  });

  final Uint8List ciphertextWithMac;
  final Uint8List commit;
}

/// Encrypt [plaintext] under a fresh 32-byte [messageKey] (AES-256-GCM + KMAC).
Future<Omemo2PayloadSeal> omemo2SealPayload({
  required Uint8List messageKey,
  required List<int> plaintext,
  required Uint8List binding,
}) async {
  final derived = kmac256(
    key: messageKey,
    data: binding,
    lengthBits: 352,
    customization: omemo2PayloadKmacLabel,
  );
  final aesKey = derived.sublist(0, 32);
  final iv = derived.sublist(32, 44);
  final cipher = AesGcm.with256bits();
  final box = await cipher.encrypt(
    plaintext,
    secretKey: SecretKey(aesKey),
    nonce: iv,
    aad: binding,
  );
  final commit = kmac256(
    key: messageKey,
    data: binding,
    lengthBits: 512,
    customization: omemo2CommitKmacLabel,
  );
  return Omemo2PayloadSeal(
    ciphertextWithMac: Uint8List.fromList([
      ...box.cipherText,
      ...box.mac.bytes,
    ]),
    commit: commit,
  );
}

/// Open a sealed payload; verifies [commit] before AES-GCM decrypt.
Future<Uint8List> omemo2OpenPayload({
  required Uint8List messageKey,
  required List<int> ciphertextWithMac,
  required List<int> commit,
  required Uint8List binding,
}) async {
  final expected = kmac256(
    key: messageKey,
    data: binding,
    lengthBits: 512,
    customization: omemo2CommitKmacLabel,
  );
  if (expected.length != commit.length) {
    throw StateError('OMEMO2 commit length mismatch');
  }
  var diff = 0;
  for (var i = 0; i < expected.length; i++) {
    diff |= expected[i] ^ commit[i];
  }
  if (diff != 0) {
    throw StateError('OMEMO2 commit mismatch');
  }

  final derived = kmac256(
    key: messageKey,
    data: binding,
    lengthBits: 352,
    customization: omemo2PayloadKmacLabel,
  );
  final aesKey = derived.sublist(0, 32);
  final iv = derived.sublist(32, 44);
  if (ciphertextWithMac.length < 16) {
    throw StateError('OMEMO2 payload too short');
  }
  final ct = ciphertextWithMac.sublist(0, ciphertextWithMac.length - 16);
  final mac = ciphertextWithMac.sublist(ciphertextWithMac.length - 16);
  final cipher = AesGcm.with256bits();
  final clear = await cipher.decrypt(
    SecretBox(ct, nonce: iv, mac: Mac(mac)),
    secretKey: SecretKey(aesKey),
    aad: binding,
  );
  return Uint8List.fromList(clear);
}
