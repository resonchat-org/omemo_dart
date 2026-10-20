import 'dart:typed_data';

import 'package:libsignal/libsignal.dart' as ls;

/// One published ML-KEM prekey as it appears in the bundle (tagged `0x0A‖pk`).
typedef Omemo2KemOneTime = ({int id, List<int> publicKey});

/// 64-byte KEM binding (monocles `PqBundle.kemBinding` / libsignal).
Uint8List omemo2KemBinding({
  required int kemSignedPreKeyId,
  required List<int> kemSignedPreKeyPublic,
  required List<Omemo2KemOneTime> oneTime,
}) {
  return ls.pqKemBinding(
    kemSignedPreKeyId: kemSignedPreKeyId,
    kemSignedPreKeyPublic: kemSignedPreKeyPublic,
    oneTime: [
      for (final k in oneTime)
        ls.KemOneTimeKey(id: k.id, publicKey: Uint8List.fromList(k.publicKey)),
    ],
  );
}

/// Identity transcript signed by ML-DSA-87 and the classical IK.
Uint8List omemo2BundleTranscript({
  required List<int> identityKey,
  required List<int> pqIdentityKey,
  required int signedPreKeyId,
  required List<int> signedPreKeyPublic,
  required List<int> kemBinding,
}) {
  return ls.pqBundleTranscript(
    identityKey: identityKey,
    pqIdentityKey: pqIdentityKey,
    signedPreKeyId: signedPreKeyId,
    signedPreKeyPublic: signedPreKeyPublic,
    kemBinding: kemBinding,
  );
}

/// Native ML-DSA-87 verify (libsignal). App ML-DSA stays on pqcrypto.
bool omemo2VerifyMlDsa({
  required List<int> publicKey,
  required List<int> message,
  required List<int> signature,
}) {
  return ls.PqIdentityKey.deserialize(
    bytes: Uint8List.fromList(publicKey),
  ).verify(
    message: Uint8List.fromList(message),
    signature: ls.PqSignature.deserialize(bytes: Uint8List.fromList(signature)),
  );
}

/// Native ML-DSA-87 key. [sign] uses this same key (transcript includes the public key).
({Uint8List publicKey, Uint8List Function(List<int> message) sign})
omemo2GenerateMlDsa() {
  final pair = ls.PqIdentityKeyPair.generate();
  final pk = pair.publicKey().serialize();
  return (
    publicKey: pk,
    sign: (message) =>
        pair.sign(message: Uint8List.fromList(message)).serialize(),
  );
}

/// Classical XEdDSA verify of [signature] over [message] under [identityKey]
/// (`IdentityKey.serialize()`, 33 bytes, leading `0x05`).
bool omemo2VerifyIdentitySignature({
  required List<int> identityKey,
  required List<int> message,
  required List<int> signature,
}) {
  return ls.PublicKey.deserialize(
    bytes: identityKey,
  ).verify(message: message, signature: signature);
}

/// Both bundle signatures over the v4 transcript. Null when they match.
///
/// XML stays in the app. Kem binding and the two verifies stay here so the
/// barrel does not export the pieces separately.
String? omemo2CheckSignatures({
  required List<int> identityKey,
  required List<int> pqIdentityKey,
  required List<int> pqSignature,
  required List<int> ikSignature,
  required int signedPreKeyId,
  required List<int> signedPreKeyPublic,
  required int kemSignedPreKeyId,
  required List<int> kemSignedPreKeyPublic,
  required List<Omemo2KemOneTime> kemOneTime,
}) {
  final binding = omemo2KemBinding(
    kemSignedPreKeyId: kemSignedPreKeyId,
    kemSignedPreKeyPublic: kemSignedPreKeyPublic,
    oneTime: kemOneTime,
  );
  final transcript = omemo2BundleTranscript(
    identityKey: identityKey,
    pqIdentityKey: pqIdentityKey,
    signedPreKeyId: signedPreKeyId,
    signedPreKeyPublic: signedPreKeyPublic,
    kemBinding: binding,
  );
  if (!omemo2VerifyMlDsa(
    publicKey: pqIdentityKey,
    message: transcript,
    signature: pqSignature,
  )) {
    return 'invalid pq-sig';
  }
  if (!omemo2VerifyIdentitySignature(
    identityKey: identityKey,
    message: transcript,
    signature: ikSignature,
  )) {
    return 'invalid ik-sig';
  }
  return null;
}
