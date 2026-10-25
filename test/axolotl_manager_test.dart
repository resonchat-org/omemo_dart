import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal_protocol_dart/libsignal_protocol_dart.dart';
import 'package:omemo_dart/omemo_dart_axolotl.dart';
import 'package:test/test.dart';

void main() {
  test('alice encrypts, bob decrypts (prekey + follow-up)', () async {
    const aliceJid = 'alice@example.com';
    const bobJid = 'bob@example.com';

    final aliceDevice = await AxolotlDevice.generateNewDevice(
      aliceJid,
      preKeyCount: 5,
    );
    final bobDevice = await AxolotlDevice.generateNewDevice(
      bobJid,
      preKeyCount: 5,
    );

    final aliceId = await aliceDevice.deviceId;
    final bobId = await bobDevice.deviceId;

    final bobBundle = await bobDevice.toBundle();
    final aliceBundle = await aliceDevice.toBundle();

    final alice = AxolotlOmemoManager(
      aliceDevice,
      fetchDeviceList: (jid) async {
        if (jid == bobJid) return [bobId];
        if (jid == aliceJid) return [aliceId];
        return null;
      },
      fetchBundle: (jid, id) async {
        if (jid == bobJid && id == bobId) return bobBundle;
        if (jid == aliceJid && id == aliceId) return aliceBundle;
        return null;
      },
    )..trackPreKeyIds(aliceDevice.store.preKeyStore.store.keys);

    final bob = AxolotlOmemoManager(
      bobDevice,
      fetchDeviceList: (jid) async {
        if (jid == aliceJid) return [aliceId];
        if (jid == bobJid) return [bobId];
        return null;
      },
      fetchBundle: (jid, id) async {
        if (jid == aliceJid && id == aliceId) return aliceBundle;
        if (jid == bobJid && id == bobId) return bobBundle;
        return null;
      },
    )..trackPreKeyIds(bobDevice.store.preKeyStore.store.keys);

    final outgoing = await alice.onOutgoingStanza(
      AxolotlOutgoingStanza(
        recipientJids: [bobJid],
        payload: utf8.encode('first message'),
      ),
    );
    expect(outgoing.canSend, isTrue);
    expect(outgoing.ciphertext, isNotNull);
    expect(outgoing.iv, isNotNull);
    final keys = outgoing.encryptedKeys[bobJid]!;
    expect(keys, hasLength(1));
    expect(keys.first.prekey, isTrue);

    final incoming = await bob.onIncomingStanza(
      AxolotlIncomingStanza(
        bareSenderJid: aliceJid,
        senderDeviceId: aliceId,
        keys: [AxolotlEncryptedKey(bobId, keys.first.value, keys.first.prekey)],
        iv: outgoing.iv,
        payload: outgoing.ciphertext,
      ),
    );
    expect(incoming.error, isNull);
    expect(incoming.payload, 'first message');

    // Follow-up (non-prekey) bob → alice
    final reply = await bob.onOutgoingStanza(
      AxolotlOutgoingStanza(
        recipientJids: [aliceJid],
        payload: utf8.encode('reply'),
      ),
    );
    expect(reply.canSend, isTrue);
    final replyKeys = reply.encryptedKeys[aliceJid]!;
    expect(replyKeys.first.prekey, isFalse);

    final replyIn = await alice.onIncomingStanza(
      AxolotlIncomingStanza(
        bareSenderJid: bobJid,
        senderDeviceId: bobId,
        keys: [
          AxolotlEncryptedKey(
            aliceId,
            replyKeys.first.value,
            replyKeys.first.prekey,
          ),
        ],
        iv: reply.iv,
        payload: reply.ciphertext,
      ),
    );
    expect(replyIn.error, isNull);
    expect(replyIn.payload, 'reply');
  });

  test('fingerprint is 66 hex chars (33-byte identity)', () async {
    final device = await AxolotlDevice.generateNewDevice(
      'x@y.z',
      preKeyCount: 1,
    );
    final fp = await device.fingerprint;
    expect(fp.length, 66);
    expect(RegExp(r'^[0-9a-f]+$').hasMatch(fp), isTrue);
  });

  test('replenishPreKeys tops up instead of appending every time', () async {
    final device = await AxolotlDevice.generateNewDevice(
      'a@b.c',
      preKeyCount: 2,
    );
    expect(device.store.preKeyStore.store.length, 2);

    final added = await device.replenishPreKeys(5);
    expect(added, hasLength(3));
    expect(device.store.preKeyStore.store.length, 5);

    final second = await device.replenishPreKeys(5);
    expect(second, isEmpty);
    expect(device.store.preKeyStore.store.length, 5);
  });

  test('published bundle caps historical prekeys', () async {
    final device = await AxolotlDevice.generateNewDevice(
      'a@b.c',
      preKeyCount: axolotlMaxPublishedPreKeyCount + 20,
    );
    final manager = AxolotlOmemoManager(
      device,
      fetchDeviceList: (_) async => null,
      fetchBundle: (_, _) async => null,
    )..trackPreKeyIds(device.store.preKeyStore.store.keys);

    final bundle = await manager.getLocalBundle();
    expect(bundle.preKeysEncoded, hasLength(axolotlMaxPublishedPreKeyCount));
  });

  test('device snapshot roundtrip preserves identity', () async {
    final device = await AxolotlDevice.generateNewDevice(
      'a@b.c',
      preKeyCount: 3,
    );
    final ids = device.store.preKeyStore.store.keys.toList();
    final snap = await device.snapshot(ids);
    final restored = await AxolotlDevice.fromSnapshot(snap);
    expect(await restored.deviceId, await device.deviceId);
    expect(await restored.fingerprint, await device.fingerprint);
  });

  test('device snapshot roundtrip keeps session records', () async {
    final device = await AxolotlDevice.generateNewDevice(
      'a@b.c',
      preKeyCount: 1,
    );
    const peer = 'peer@b.c';
    final record = Uint8List.fromList([9, 8, 7, 6]);
    device.store.sessionStore.sessions[const SignalProtocolAddress(peer, 7)] =
        record;
    final snap = await device.snapshot(
      device.store.preKeyStore.store.keys.toList(),
    );
    final restored = await AxolotlDevice.fromSnapshot(
      AxolotlDeviceSnapshot.fromJson(snap.toJson()),
    );
    expect(
      restored.store.sessionStore.sessions[const SignalProtocolAddress(
        peer,
        7,
      )],
      record,
    );
    expect(
      AxolotlDeviceSnapshot.fromJson(
        jsonDecode(jsonEncode(snap.toJson())) as Map<String, dynamic>,
      ).sessions.single.deviceId,
      7,
    );
  });
}
