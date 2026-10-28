import 'dart:typed_data';

import 'package:meta/meta.dart';

import 'package:omemo_dart/src/omemo2/kem_tag.dart';

/// Remote device bundle for monocles OMEMO2 PEP (public halves only).
@immutable
class Omemo2PreKeyBundle {
  const Omemo2PreKeyBundle({
    required this.jid,
    required this.deviceId,
    required this.identityPublicTagged,
    required this.signedPreKeyId,
    required this.signedPreKeyPublicTagged,
    required this.signedPreKeySignature,
    required this.kyberPreKeyId,
    required this.kyberPreKeyPublicTagged,
    required this.kyberPreKeySignature,
    required this.kemSignedPreKeyId,
    required this.kemSignedPreKeyPublicTagged,
    required this.kemOneTimeKeys,
    this.preKeyId,
    this.preKeyPublicTagged,
    this.pqIdentityKey,
    this.pqSignature,
    this.ikSignature,
  });

  /// Prefer a one-time KEM prekey when the map-based constructor is used.
  factory Omemo2PreKeyBundle.fromParts({
    required String jid,
    required int deviceId,
    required Uint8List identityPublicTagged,
    required int signedPreKeyId,
    required Uint8List signedPreKeyPublicTagged,
    required Uint8List signedPreKeySignature,
    required int kyberSignedPreKeyId,
    required Uint8List kyberSignedPreKeyPublicRaw,
    required Uint8List kyberSignedPreKeySignature,
    int? preKeyId,
    Uint8List? preKeyPublicTagged,
    Map<int, ({Uint8List publicRaw, Uint8List signature})> kyberOneTime =
        const {},
    Uint8List? pqIdentityKey,
    Uint8List? pqSignature,
    Uint8List? ikSignature,
  }) {
    late final int kyberId;
    late final Uint8List kyberPk;
    late final Uint8List kyberSig;
    if (kyberOneTime.isNotEmpty) {
      final e = kyberOneTime.entries.first;
      kyberId = e.key;
      kyberPk = serializeMlKem1024PublicKey(e.value.publicRaw);
      kyberSig = e.value.signature;
    } else {
      kyberId = kyberSignedPreKeyId;
      kyberPk = serializeMlKem1024PublicKey(kyberSignedPreKeyPublicRaw);
      kyberSig = kyberSignedPreKeySignature;
    }
    final kemSpkTagged = serializeMlKem1024PublicKey(
      kyberSignedPreKeyPublicRaw,
    );
    final oneTime = [
      for (final e in kyberOneTime.entries)
        (
          id: e.key,
          publicTagged: serializeMlKem1024PublicKey(e.value.publicRaw),
        ),
    ];
    return Omemo2PreKeyBundle(
      jid: jid,
      deviceId: deviceId,
      identityPublicTagged: identityPublicTagged,
      signedPreKeyId: signedPreKeyId,
      signedPreKeyPublicTagged: signedPreKeyPublicTagged,
      signedPreKeySignature: signedPreKeySignature,
      preKeyId: preKeyId,
      preKeyPublicTagged: preKeyPublicTagged,
      kyberPreKeyId: kyberId,
      kyberPreKeyPublicTagged: kyberPk,
      kyberPreKeySignature: kyberSig,
      kemSignedPreKeyId: kyberSignedPreKeyId,
      kemSignedPreKeyPublicTagged: kemSpkTagged,
      kemOneTimeKeys: oneTime,
      pqIdentityKey: pqIdentityKey,
      pqSignature: pqSignature,
      ikSignature: ikSignature,
    );
  }

  final String jid;
  final int deviceId;

  /// `0x05 ‖ ik` (33 bytes).
  final Uint8List identityPublicTagged;

  final int signedPreKeyId;
  final Uint8List signedPreKeyPublicTagged;
  final Uint8List signedPreKeySignature;

  final int? preKeyId;
  final Uint8List? preKeyPublicTagged;

  final int kyberPreKeyId;

  /// `0x0A ‖ pk` — the KEM key selected for PQXDH (one-time preferred).
  final Uint8List kyberPreKeyPublicTagged;
  final Uint8List kyberPreKeySignature;

  /// Last-resort `<kem-spk>` id / tagged public — for [pqKemBinding].
  final int kemSignedPreKeyId;
  final Uint8List kemSignedPreKeyPublicTagged;

  /// Every published `<kem-pk>` in bundle document order — for [pqKemBinding].
  final List<({int id, Uint8List publicTagged})> kemOneTimeKeys;

  /// Raw ML-DSA-87 verification key (2592), when the peer published `<pq-ik>`.
  final Uint8List? pqIdentityKey;

  /// ML-DSA-87 signature over the v4 transcript (`<pq-sig>`).
  final Uint8List? pqSignature;

  /// Classical IK XEdDSA signature over the same transcript (`<ik-sig>`).
  final Uint8List? ikSignature;

  /// monocles: all three halves required (never downgrade).
  bool get hasPqIdentity =>
      pqIdentityKey != null &&
      pqIdentityKey!.isNotEmpty &&
      pqSignature != null &&
      pqSignature!.isNotEmpty &&
      ikSignature != null &&
      ikSignature!.isNotEmpty;
}
