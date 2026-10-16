import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:libsignal/libsignal.dart' as ls;
import 'package:meta/meta.dart';
import 'package:omemo_dart/src/common/helpers.dart';
import 'package:omemo_dart/src/common/keys.dart';
import 'package:omemo_dart/src/omemo2/address.dart';
import 'package:omemo_dart/src/omemo2/bootstrap.dart';
import 'package:omemo_dart/src/omemo2/bundle.dart';
import 'package:omemo_dart/src/omemo2/constants.dart';
import 'package:omemo_dart/src/omemo2/kem_tag.dart';

/// One-time ML-KEM prekey (raw FIPS 203 bytes + XEdDSA signature).
@immutable
class Omemo2KyberPreKey {
  const Omemo2KyberPreKey({
    required this.publicRaw,
    required this.secretRaw,
    required this.signature,
  });

  final Uint8List publicRaw;
  final Uint8List secretRaw;
  final Uint8List signature;
}

/// Local monocles OMEMO2 device (classical + ML-KEM-1024 key material).
class Omemo2Device {
  Omemo2Device({
    required this.jid,
    required this.id,
    required this.ikEd,
    required this.ikDh,
    required this.spk,
    required this.spkId,
    required this.spkSignature,
    required this.pqSpk,
    required this.pqSpkSecret,
    required this.pqSpkId,
    required this.pqSpkSignature,
    required this.opks,
    required this.pqOpks,
    this.peerPqIdentityKey,
    this.peerPqSignature,
    this.peerIkSignature,
  });

  final String jid;
  final int id;

  final OmemoKeyPair ikEd;
  final OmemoKeyPair ikDh;
  final OmemoKeyPair spk;
  final int spkId;
  final Uint8List spkSignature;

  final Uint8List pqSpk;
  final Uint8List pqSpkSecret;
  final int pqSpkId;
  final Uint8List pqSpkSignature;

  final Map<int, OmemoKeyPair> opks;
  final Map<int, Omemo2KyberPreKey> pqOpks;

  /// Remote-only: ML-DSA-87 public key from the peer's published `<pq-ik>`.
  /// Local devices leave this null (signing lives in the app identity store).
  final Uint8List? peerPqIdentityKey;

  /// Remote-only: `<pq-sig>` over the published bundle transcript.
  final Uint8List? peerPqSignature;

  /// Remote-only: classical IK `<ik-sig>` over the same transcript (v4).
  final Uint8List? peerIkSignature;

  late ls.InMemorySessionStore _sessionStore;
  late ls.InMemoryIdentityKeyStore _identityStore;
  late ls.InMemoryPreKeyStore _preKeyStore;
  late ls.InMemorySignedPreKeyStore _signedPreKeyStore;
  late ls.InMemoryKyberPreKeyStore _kyberPreKeyStore;
  ls.ProtocolAddress? _localAddress;
  bool _storesReady = false;

  ls.ProtocolAddress get localAddress =>
      _localAddress ?? omemo2ProtocolAddress(jid, id);

  ls.InMemorySessionStore get sessionStore => _sessionStore;
  ls.InMemoryIdentityKeyStore get identityStore => _identityStore;
  ls.InMemoryPreKeyStore get preKeyStore => _preKeyStore;
  ls.InMemorySignedPreKeyStore get signedPreKeyStore => _signedPreKeyStore;
  ls.InMemoryKyberPreKeyStore get kyberPreKeyStore => _kyberPreKeyStore;

  static Future<Omemo2Device> generate(
    String jid, {
    int opkCount = 20,
    int pqOpkCount = 5,

    /// When set, use this registration id (monocles announces the same
    /// numeric id on classic and OMEMO2 lists; key material stays separate).
    int? deviceId,
  }) async {
    await omemo2EnsureLibSignal();

    final ikEd = await OmemoKeyPair.generateNewPair(KeyPairType.ed25519);
    final ik = await ikEd.toCurve25519();
    final ikPriv = Uint8List.fromList(await ik.sk.getBytes());
    final idPair = _identityFromPrivate(ikPriv);

    final spk = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    final spkId = generateRandomOmemoId();
    final spkSerialized = Uint8List.fromList([
      0x05,
      ...await spk.pk.getBytes(),
    ]);
    final spkSig = idPair.sign(message: spkSerialized);

    final opks = <int, OmemoKeyPair>{};
    for (var i = 0; i < opkCount; i++) {
      opks[generateRandomOmemoId()] = await OmemoKeyPair.generateNewPair(
        KeyPairType.x25519,
      );
    }

    final pqSpkKp = ls.KyberKeyPair.generate();
    final pqSpkTagged = pqSpkKp.getPublicKey().serialize();
    final pqSpkSecretTagged = pqSpkKp.getSecretKey().serialize();
    final pqSpkId = generateRandomOmemoId();
    final pqSpkSig = idPair.sign(message: pqSpkTagged);

    final pqOpks = <int, Omemo2KyberPreKey>{};
    for (var i = 0; i < pqOpkCount; i++) {
      final id = generateRandomOmemoId();
      final kp = ls.KyberKeyPair.generate();
      final pubTagged = kp.getPublicKey().serialize();
      final skTagged = kp.getSecretKey().serialize();
      pqOpks[id] = Omemo2KyberPreKey(
        publicRaw: pubTagged.sublist(1),
        secretRaw: skTagged.sublist(1),
        signature: idPair.sign(message: pubTagged),
      );
    }

    return Omemo2Device(
      jid: jid,
      id: deviceId ?? generateRandomOmemoId(),
      ikEd: ikEd,
      ikDh: ik,
      spk: spk,
      spkId: spkId,
      spkSignature: spkSig,
      pqSpk: pqSpkTagged.sublist(1),
      pqSpkSecret: pqSpkSecretTagged.sublist(1),
      pqSpkId: pqSpkId,
      pqSpkSignature: pqSpkSig,
      opks: opks,
      pqOpks: pqOpks,
    );
  }

  static ls.IdentityKeyPair _identityFromPrivate(Uint8List private32) {
    final sk = ls.PrivateKey.deserialize(bytes: private32);
    return ls.IdentityKeyPair.fromKeys(
      privateKey: sk,
      publicKey: sk.getPublicKey(),
    );
  }

  Future<void> ensureStores() async {
    if (_storesReady) return;
    await omemo2EnsureLibSignal();

    final ikPriv = Uint8List.fromList(await ikDh.sk.getBytes());
    final identity = _identityFromPrivate(ikPriv);
    _localAddress = omemo2ProtocolAddress(jid, id);
    _sessionStore = ls.InMemorySessionStore();
    _identityStore = ls.InMemoryIdentityKeyStore(identity, 0);
    _preKeyStore = ls.InMemoryPreKeyStore();
    _signedPreKeyStore = ls.InMemorySignedPreKeyStore();
    _kyberPreKeyStore = ls.InMemoryKyberPreKeyStore();

    final ts = BigInt.from(DateTime.now().millisecondsSinceEpoch);
    final spkSk = ls.PrivateKey.deserialize(bytes: await spk.sk.getBytes());
    await _signedPreKeyStore.storeSignedPreKey(
      spkId,
      ls.SignedPreKeyRecord(
        id: spkId,
        timestamp: ts,
        publicKey: spkSk.getPublicKey(),
        privateKey: spkSk,
        signature: spkSignature,
      ),
    );

    for (final e in opks.entries) {
      final sk = ls.PrivateKey.deserialize(bytes: await e.value.sk.getBytes());
      await _preKeyStore.storePreKey(
        e.key,
        ls.PreKeyRecord(
          id: e.key,
          publicKey: sk.getPublicKey(),
          privateKey: sk,
        ),
      );
    }

    Future<void> storeKyber(
      int kid,
      Uint8List pub,
      Uint8List secret,
      Uint8List sig,
    ) async {
      final pubKey = ls.KyberPublicKey.deserialize(
        bytes: serializeMlKem1024PublicKey(pub),
      );
      final secretKey = ls.KyberSecretKey.deserialize(
        bytes: Uint8List.fromList([omemo2MlKem1024Tag, ...secret]),
      );
      final pair = ls.KyberKeyPair.fromKeys(
        publicKey: pubKey,
        secretKey: secretKey,
      );
      await _kyberPreKeyStore.storeKyberPreKey(
        kid,
        ls.KyberPreKeyRecord.create(
          id: kid,
          timestamp: ts,
          keyPair: pair,
          signature: sig,
        ),
      );
    }

    await storeKyber(pqSpkId, pqSpk, pqSpkSecret, pqSpkSignature);
    for (final e in pqOpks.entries) {
      await storeKyber(
        e.key,
        e.value.publicRaw,
        e.value.secretRaw,
        e.value.signature,
      );
    }
    _storesReady = true;
  }

  ls.SessionCipher sessionCipher() => ls.SessionCipher(
    localAddress: localAddress,
    sessionStore: sessionStore,
    identityKeyStore: identityStore,
    preKeyStore: preKeyStore,
    signedPreKeyStore: signedPreKeyStore,
    kyberPreKeyStore: kyberPreKeyStore,
  );

  /// Public bundle for PEP (prefers a one-time KEM prekey when available).
  Future<Omemo2PreKeyBundle> toBundle() async {
    MapEntry<int, OmemoKeyPair>? opk;
    if (opks.isNotEmpty) opk = opks.entries.first;

    return Omemo2PreKeyBundle.fromParts(
      jid: jid,
      deviceId: id,
      identityPublicTagged: Uint8List.fromList([
        0x05,
        ...await ikDh.pk.getBytes(),
      ]),
      signedPreKeyId: spkId,
      signedPreKeyPublicTagged: Uint8List.fromList([
        0x05,
        ...await spk.pk.getBytes(),
      ]),
      signedPreKeySignature: spkSignature,
      preKeyId: opk?.key,
      preKeyPublicTagged: opk == null
          ? null
          : Uint8List.fromList([0x05, ...await opk.value.pk.getBytes()]),
      kyberSignedPreKeyId: pqSpkId,
      kyberSignedPreKeyPublicRaw: pqSpk,
      kyberSignedPreKeySignature: pqSpkSignature,
      kyberOneTime: {
        for (final e in pqOpks.entries)
          e.key: (publicRaw: e.value.publicRaw, signature: e.value.signature),
      },
      pqIdentityKey: peerPqIdentityKey,
      pqSignature: peerPqSignature,
      ikSignature: peerIkSignature,
    );
  }

  Future<Uint8List> sign(List<int> message) async {
    await omemo2EnsureLibSignal();
    final ikPriv = Uint8List.fromList(await ikDh.sk.getBytes());
    return _identityFromPrivate(ikPriv).sign(message: message);
  }

  /// Classical identity as libsignal `IdentityKey.serialize()` (33 bytes,
  /// leading `0x05`) — the same encoding monocles hashes into the hybrid
  /// fingerprint and publishes as the session identity.
  Future<Uint8List> identityPublicSerialized() async {
    await omemo2EnsureLibSignal();
    final ikPriv = Uint8List.fromList(await ikDh.sk.getBytes());
    return _identityFromPrivate(ikPriv).publicKey;
  }

  /// Persistable key material (no session ratchet state).
  Future<Omemo2DeviceSnapshot> snapshot() async {
    Future<Map<String, String>> keyPairJson(OmemoKeyPair kp) async => {
      'type': kp.type.name,
      'pk': base64Encode(await kp.pk.getBytes()),
      'sk': base64Encode(await kp.sk.getBytes()),
    };

    return Omemo2DeviceSnapshot(
      jid: jid,
      id: id,
      ikEd: await keyPairJson(ikEd),
      ikDh: await keyPairJson(ikDh),
      spk: await keyPairJson(spk),
      spkId: spkId,
      spkSignature: base64Encode(spkSignature),
      pqSpk: base64Encode(pqSpk),
      pqSpkSecret: base64Encode(pqSpkSecret),
      pqSpkId: pqSpkId,
      pqSpkSignature: base64Encode(pqSpkSignature),
      opks: {
        for (final e in opks.entries) '${e.key}': await keyPairJson(e.value),
      },
      pqOpks: {
        for (final e in pqOpks.entries)
          '${e.key}': {
            'pk': base64Encode(e.value.publicRaw),
            'sk': base64Encode(e.value.secretRaw),
            'sig': base64Encode(e.value.signature),
          },
      },
    );
  }

  /// Restore from [Omemo2DeviceSnapshot]. Call [ensureStores] before crypto use.
  static Future<Omemo2Device> fromSnapshot(Omemo2DeviceSnapshot snap) async {
    OmemoKeyPair keyPair(Map<String, String> m) {
      final type = switch (m['type']) {
        'ed25519' => KeyPairType.ed25519,
        _ => KeyPairType.x25519,
      };
      return OmemoKeyPair.fromBytes(
        base64Decode(m['pk']!),
        base64Decode(m['sk']!),
        type,
      );
    }

    final opks = <int, OmemoKeyPair>{};
    for (final e in snap.opks.entries) {
      opks[int.parse(e.key)] = keyPair(e.value);
    }
    final pqOpks = <int, Omemo2KyberPreKey>{};
    for (final e in snap.pqOpks.entries) {
      pqOpks[int.parse(e.key)] = Omemo2KyberPreKey(
        publicRaw: Uint8List.fromList(base64Decode(e.value['pk']!)),
        secretRaw: Uint8List.fromList(base64Decode(e.value['sk']!)),
        signature: Uint8List.fromList(base64Decode(e.value['sig']!)),
      );
    }

    return Omemo2Device(
      jid: snap.jid,
      id: snap.id,
      ikEd: keyPair(snap.ikEd),
      ikDh: keyPair(snap.ikDh),
      spk: keyPair(snap.spk),
      spkId: snap.spkId,
      spkSignature: Uint8List.fromList(base64Decode(snap.spkSignature)),
      pqSpk: Uint8List.fromList(base64Decode(snap.pqSpk)),
      pqSpkSecret: Uint8List.fromList(base64Decode(snap.pqSpkSecret)),
      pqSpkId: snap.pqSpkId,
      pqSpkSignature: Uint8List.fromList(base64Decode(snap.pqSpkSignature)),
      opks: opks,
      pqOpks: pqOpks,
    );
  }
}

/// Serializable OMEMO2 device key material (no active sessions).
@immutable
class Omemo2DeviceSnapshot {
  const Omemo2DeviceSnapshot({
    required this.jid,
    required this.id,
    required this.ikEd,
    required this.ikDh,
    required this.spk,
    required this.spkId,
    required this.spkSignature,
    required this.pqSpk,
    required this.pqSpkSecret,
    required this.pqSpkId,
    required this.pqSpkSignature,
    required this.opks,
    required this.pqOpks,
  });

  factory Omemo2DeviceSnapshot.fromJson(Map<String, dynamic> json) {
    Map<String, String> kp(dynamic raw) =>
        (raw as Map<String, dynamic>).map((k, v) => MapEntry(k, v as String));
    Map<String, Map<String, String>> mapOfMaps(dynamic raw) {
      final out = <String, Map<String, String>>{};
      for (final e in (raw as Map<String, dynamic>? ?? {}).entries) {
        out[e.key] = (e.value as Map<String, dynamic>).map(
          (k, v) => MapEntry(k, v as String),
        );
      }
      return out;
    }

    return Omemo2DeviceSnapshot(
      jid: json['jid'] as String,
      id: json['id'] as int,
      ikEd: kp(json['ikEd']),
      ikDh: kp(json['ikDh']),
      spk: kp(json['spk']),
      spkId: json['spkId'] as int,
      spkSignature: json['spkSignature'] as String,
      pqSpk: json['pqSpk'] as String,
      pqSpkSecret: json['pqSpkSecret'] as String,
      pqSpkId: json['pqSpkId'] as int,
      pqSpkSignature: json['pqSpkSignature'] as String,
      opks: mapOfMaps(json['opks']),
      pqOpks: mapOfMaps(json['pqOpks']),
    );
  }

  final String jid;
  final int id;
  final Map<String, String> ikEd;
  final Map<String, String> ikDh;
  final Map<String, String> spk;
  final int spkId;
  final String spkSignature;
  final String pqSpk;
  final String pqSpkSecret;
  final int pqSpkId;
  final String pqSpkSignature;
  final Map<String, Map<String, String>> opks;
  final Map<String, Map<String, String>> pqOpks;

  Map<String, dynamic> toJson() => {
    'jid': jid,
    'id': id,
    'ikEd': ikEd,
    'ikDh': ikDh,
    'spk': spk,
    'spkId': spkId,
    'spkSignature': spkSignature,
    'pqSpk': pqSpk,
    'pqSpkSecret': pqSpkSecret,
    'pqSpkId': pqSpkId,
    'pqSpkSignature': pqSpkSignature,
    'opks': opks,
    'pqOpks': pqOpks,
  };
}
