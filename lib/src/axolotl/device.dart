import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal_protocol_dart/libsignal_protocol_dart.dart';
import 'package:meta/meta.dart';
import 'package:omemo_dart/src/axolotl/bundle.dart';
import 'package:omemo_dart/src/axolotl/constants.dart';
import 'package:omemo_dart/src/axolotl/fingerprint.dart';
import 'package:omemo_dart/src/common/helpers.dart';

/// Local OMEMO 0.3.0 / Conversations device (Signal Protocol identity).
class AxolotlDevice {
  AxolotlDevice({
    required this.jid,
    required this.store,
    required this.signedPreKeyId,
  });

  /// Create a brand-new device with fresh identity and prekey pool.
  static Future<AxolotlDevice> generateNewDevice(
    String jid, {
    int preKeyCount = axolotlDefaultPreKeyCount,
  }) async {
    final identityKeyPair = generateIdentityKeyPair();
    // Conversations uses KeyHelper.generateRegistrationId(true) → [1, MAX-1].
    final registrationId = generateRegistrationId(true);
    final store = InMemorySignalProtocolStore(identityKeyPair, registrationId);

    final signedPreKeyId = generateRandomOmemoId();
    final signedPreKey = generateSignedPreKey(identityKeyPair, signedPreKeyId);
    await store.storeSignedPreKey(signedPreKeyId, signedPreKey);

    final start = generateRandomOmemoId();
    final preKeys = generatePreKeys(start, preKeyCount);
    for (final pk in preKeys) {
      await store.storePreKey(pk.id, pk);
    }

    return AxolotlDevice(
      jid: jid,
      store: store,
      signedPreKeyId: signedPreKeyId,
    );
  }

  final String jid;
  final InMemorySignalProtocolStore store;
  int signedPreKeyId;

  Future<int> get deviceId async => store.getLocalRegistrationId();

  Future<IdentityKeyPair> get identityKeyPair async =>
      store.getIdentityKeyPair();

  Future<String> get fingerprint async {
    final ik = (await identityKeyPair).getPublicKey();
    return axolotlFingerprint(ik);
  }

  /// Build the PEP bundle for this device. [preKeyIds] limits which one-time
  /// keys are published; when null, every stored prekey is included.
  Future<AxolotlBundle> toBundle({Iterable<int>? preKeyIds}) async {
    final id = await deviceId;
    final identity = await identityKeyPair;
    final signed = await store.loadSignedPreKey(signedPreKeyId);

    final ids = preKeyIds?.toList() ?? store.preKeyStore.store.keys.toList();
    final preKeys = <int, String>{};
    for (final pkId in ids) {
      if (!await store.containsPreKey(pkId)) continue;
      final record = await store.loadPreKey(pkId);
      preKeys[pkId] = base64Encode(record.getKeyPair().publicKey.serialize());
    }

    return AxolotlBundle(
      jid: jid,
      deviceId: id,
      signedPreKeyId: signedPreKeyId,
      signedPreKeyPublicEncoded: base64Encode(
        signed.getKeyPair().publicKey.serialize(),
      ),
      signedPreKeySignatureEncoded: base64Encode(signed.signature),
      identityKeyEncoded: base64Encode(identity.getPublicKey().serialize()),
      preKeysEncoded: preKeys,
      registrationId: id,
    );
  }

  /// Ensure at least [count] one-time prekeys exist; returns newly created ids.
  ///
  /// This is a top-up, not an append: calling it on every connect must not
  /// grow the pool (and the published bundle) without bound.
  Future<List<int>> replenishPreKeys(int count) async {
    final missing = count - store.preKeyStore.store.length;
    if (missing <= 0) return const [];
    final start = generateRandomOmemoId();
    final created = generatePreKeys(start, missing);
    final ids = <int>[];
    for (final pk in created) {
      await store.storePreKey(pk.id, pk);
      ids.add(pk.id);
    }
    return ids;
  }

  /// Rotate the signed prekey; returns the new id.
  Future<int> rotateSignedPreKey() async {
    final identity = await identityKeyPair;
    final newId = generateRandomOmemoId();
    final record = generateSignedPreKey(identity, newId);
    await store.storeSignedPreKey(newId, record);
    signedPreKeyId = newId;
    return newId;
  }

  /// Snapshot for persistence: identity, prekeys, and every [SessionRecord].
  ///
  /// Conversations writes the session inside `storeSession` (encrypt and
  /// decrypt) and only drops the table in `wipeAxolotlDb`. The records travel
  /// with this snapshot so one commit keeps the same lifecycle.
  Future<AxolotlDeviceSnapshot> snapshot(List<int> preKeyIds) async {
    final identity = await identityKeyPair;
    final regId = await deviceId;
    final signed = await store.loadSignedPreKey(signedPreKeyId);
    final preKeys = <int, List<int>>{};
    for (final id in preKeyIds) {
      if (!await store.containsPreKey(id)) continue;
      final record = await store.loadPreKey(id);
      preKeys[id] = record.serialize().toList();
    }
    return AxolotlDeviceSnapshot(
      jid: jid,
      registrationId: regId,
      identityPrivateKey: identity.getPrivateKey().serialize().toList(),
      identityPublicKey: identity.getPublicKey().serialize().toList(),
      signedPreKeyId: signedPreKeyId,
      signedPreKeyRecord: signed.serialize().toList(),
      preKeyRecords: preKeys,
      sessions: [
        for (final entry in store.sessionStore.sessions.entries)
          AxolotlStoredSession(
            name: entry.key.getName(),
            deviceId: entry.key.getDeviceId(),
            record: entry.value.toList(),
          ),
      ],
    );
  }

  /// Restore from [AxolotlDeviceSnapshot].
  static Future<AxolotlDevice> fromSnapshot(AxolotlDeviceSnapshot snap) async {
    final identity = generateIdentityKeyPairFromPrivate(
      snap.identityPrivateKey,
    );
    final store = InMemorySignalProtocolStore(identity, snap.registrationId);
    final signed = SignedPreKeyRecord.fromSerialized(
      Uint8List.fromList(snap.signedPreKeyRecord),
    );
    await store.storeSignedPreKey(snap.signedPreKeyId, signed);
    for (final entry in snap.preKeyRecords.entries) {
      final record = PreKeyRecord.fromBuffer(Uint8List.fromList(entry.value));
      await store.storePreKey(entry.key, record);
    }
    for (final session in snap.sessions) {
      store.sessionStore.sessions[SignalProtocolAddress(
        session.name,
        session.deviceId,
      )] = Uint8List.fromList(
        session.record,
      );
    }
    return AxolotlDevice(
      jid: snap.jid,
      store: store,
      signedPreKeyId: snap.signedPreKeyId,
    );
  }
}

/// One persisted libsignal [SessionRecord] (peer JID + device id).
@immutable
class AxolotlStoredSession {
  const AxolotlStoredSession({
    required this.name,
    required this.deviceId,
    required this.record,
  });

  final String name;
  final int deviceId;
  final List<int> record;
}

/// Serializable device key material, including active sessions.
@immutable
class AxolotlDeviceSnapshot {
  const AxolotlDeviceSnapshot({
    required this.jid,
    required this.registrationId,
    required this.identityPrivateKey,
    required this.identityPublicKey,
    required this.signedPreKeyId,
    required this.signedPreKeyRecord,
    required this.preKeyRecords,
    this.sessions = const [],
  });

  factory AxolotlDeviceSnapshot.fromJson(Map<String, dynamic> json) {
    final pre = <int, List<int>>{};
    final raw = json['preKeyRecords'] as Map<String, dynamic>? ?? {};
    for (final e in raw.entries) {
      pre[int.parse(e.key)] = base64Decode(e.value as String);
    }
    final sessions = <AxolotlStoredSession>[];
    final rawSessions = json['sessions'];
    if (rawSessions is List) {
      for (final item in rawSessions) {
        if (item is! Map) continue;
        final name = item['name'];
        final deviceId = item['deviceId'];
        final record = item['record'];
        if (name is! String || deviceId is! int || record is! String) continue;
        sessions.add(
          AxolotlStoredSession(
            name: name,
            deviceId: deviceId,
            record: base64Decode(record),
          ),
        );
      }
    }
    return AxolotlDeviceSnapshot(
      jid: json['jid'] as String,
      registrationId: json['registrationId'] as int,
      identityPrivateKey: base64Decode(json['identityPrivateKey'] as String),
      identityPublicKey: base64Decode(json['identityPublicKey'] as String),
      signedPreKeyId: json['signedPreKeyId'] as int,
      signedPreKeyRecord: base64Decode(json['signedPreKeyRecord'] as String),
      preKeyRecords: pre,
      sessions: sessions,
    );
  }

  final String jid;
  final int registrationId;
  final List<int> identityPrivateKey;
  final List<int> identityPublicKey;
  final int signedPreKeyId;
  final List<int> signedPreKeyRecord;
  final Map<int, List<int>> preKeyRecords;

  /// Ratchet state per remote device. Empty on blobs written before sessions
  /// were included; those devices rebuild a session from the next bundle.
  final List<AxolotlStoredSession> sessions;

  Map<String, dynamic> toJson() => {
    'jid': jid,
    'registrationId': registrationId,
    'identityPrivateKey': base64Encode(identityPrivateKey),
    'identityPublicKey': base64Encode(identityPublicKey),
    'signedPreKeyId': signedPreKeyId,
    'signedPreKeyRecord': base64Encode(signedPreKeyRecord),
    'preKeyRecords': {
      for (final e in preKeyRecords.entries) '${e.key}': base64Encode(e.value),
    },
    'sessions': [
      for (final s in sessions)
        {
          'name': s.name,
          'deviceId': s.deviceId,
          'record': base64Encode(s.record),
        },
    ],
  };
}
