import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import 'package:omemo_dart/omemo_dart_omemo2.dart';
import 'package:omemo_dart/src/omemo2/bundle_transcript.dart';

void main() {
  setUpAll(() async {
    await omemo2EnsureLibSignal();
  });

  test('Kyber generate uses ML-KEM-1024 tag 0x0A', () async {
    final d = await Omemo2Device.generate('a@example.org', pqOpkCount: 1);
    final tagged = serializeMlKem1024PublicKey(d.pqSpk);
    expect(tagged[0], omemo2MlKem1024Tag);
  });

  test('device PQ one-time pool is sized and distinct', () async {
    final d = await Omemo2Device.generate(
      'me@example.org',
      opkCount: 2,
      pqOpkCount: 4,
    );
    expect(d.pqOpks.length, 4);
    final publics = d.pqOpks.values.map((e) => e.publicRaw).toList();
    expect(
      publics.every((p) => p.length == omemo2MlKemPublicKeyLength),
      isTrue,
    );
    expect(
      d.pqOpks.values.every(
        (e) => e.secretRaw.length == omemo2MlKemSecretKeyLength,
      ),
      isTrue,
    );
    expect({for (final p in publics) base64Encode(p)}.length, publics.length);
  });

  Future<Omemo2PreKeyBundle> signedBundle(Omemo2Device device) async {
    final pq = omemo2GenerateMlDsa();
    final transcript = await device.identityTranscript(pq.publicKey);
    final pqSig = pq.sign(transcript);
    final ikSig = await device.sign(transcript);
    final opk = device.opks.entries.first;
    final spkRaw = await device.spk.pk.getBytes();
    final opkRaw = await opk.value.pk.getBytes();
    return Omemo2PreKeyBundle.fromParts(
      jid: device.jid,
      deviceId: device.id,
      identityPublicTagged: await device.identityPublicSerialized(),
      signedPreKeyId: device.spkId,
      signedPreKeyPublicTagged: Uint8List.fromList([0x05, ...spkRaw]),
      signedPreKeySignature: device.spkSignature,
      preKeyId: opk.key,
      preKeyPublicTagged: Uint8List.fromList([0x05, ...opkRaw]),
      kyberSignedPreKeyId: device.pqSpkId,
      kyberSignedPreKeyPublicRaw: device.pqSpk,
      kyberSignedPreKeySignature: device.pqSpkSignature,
      kyberOneTime: {
        for (final e in device.pqOpks.entries)
          e.key: (publicRaw: e.value.publicRaw, signature: e.value.signature),
      },
      pqIdentityKey: pq.publicKey,
      pqSignature: pqSig,
      ikSignature: ikSig,
    );
  }

  Future<(Omemo2Manager, Omemo2Manager, Omemo2Device, Omemo2Device)> pair({
    int alicePqOpk = 1,
    int bobPqOpk = 1,
  }) async {
    final aliceDev = await Omemo2Device.generate(
      'alice@example.org',
      opkCount: 2,
      pqOpkCount: alicePqOpk,
    );
    final bobDev = await Omemo2Device.generate(
      'bob@example.org',
      opkCount: 2,
      pqOpkCount: bobPqOpk,
    );
    final aliceBundle = await signedBundle(aliceDev);
    final bobBundle = await signedBundle(bobDev);
    Omemo2PreKeyBundle? bundleOf(String jid, int id) {
      if (jid == bobDev.jid && id == bobDev.id) return bobBundle;
      if (jid == aliceDev.jid && id == aliceDev.id) return aliceBundle;
      return null;
    }

    final alice = Omemo2Manager(
      aliceDev,
      fetchDeviceList: (jid) async {
        if (jid == bobDev.jid) return [bobDev.id];
        if (jid == aliceDev.jid) return [aliceDev.id];
        return null;
      },
      fetchBundle: (jid, id) async => bundleOf(jid, id),
    );
    final bob = Omemo2Manager(
      bobDev,
      fetchDeviceList: (jid) async {
        if (jid == aliceDev.jid) return [aliceDev.id];
        if (jid == bobDev.jid) return [bobDev.id];
        return null;
      },
      fetchBundle: (jid, id) async => bundleOf(jid, id),
    );
    await alice.onDeviceListUpdate(bobDev.jid, [bobDev.id]);
    await bob.onDeviceListUpdate(aliceDev.jid, [aliceDev.id]);
    return (alice, bob, aliceDev, bobDev);
  }

  test('Omemo2Manager round-trip with SPQR (KEX)', () async {
    final (alice, bob, aliceDev, bobDev) = await pair();

    final enc = await alice.onOutgoingStanza(
      Omemo2OutgoingStanza(
        recipientJids: [bobDev.jid],
        payload: utf8.encode('hello PQ'),
      ),
    );
    expect(enc.canSend, isTrue);
    expect(enc.ciphertext, isNotNull);
    expect(enc.commit, isNotNull);
    final key = enc.encryptedKeys[bobDev.jid]!.single;
    expect(key.kex, isTrue);

    final keyBytes = Uint8List.fromList(key.data);
    final whisper = PreKeySignalMessage.deserialize(data: keyBytes);
    expect(whisper.message().pqRatchet(), isNotNull);

    final preKey = Omemo2PreKeySignalMessage.fromSerialized(keyBytes);
    expect(bobDev.pqOpks.containsKey(preKey.kyberPreKeyId), isTrue);
    expect(
      preKey.kyberCiphertextTagged.length,
      1 + omemo2MlKemCiphertextLength,
    );

    final dec = await bob.onIncomingStanza(
      Omemo2IncomingStanza(
        bareSenderJid: aliceDev.jid,
        senderDeviceId: aliceDev.id,
        recipientBareJid: bobDev.jid,
        keys: [key],
        payload: enc.ciphertext,
        commit: enc.commit,
      ),
    );
    expect(dec.error, isNull);
    expect(dec.payload, 'hello PQ');
  });

  test('follow-up messages reuse session without KEX', () async {
    final (alice, bob, aliceDev, bobDev) = await pair();

    final first = await alice.onOutgoingStanza(
      Omemo2OutgoingStanza(
        recipientJids: [bobDev.jid],
        payload: utf8.encode('message 0'),
      ),
    );
    expect(first.encryptedKeys[bobDev.jid]!.single.kex, isTrue);
    expect(
      (await bob.onIncomingStanza(
        Omemo2IncomingStanza(
          bareSenderJid: aliceDev.jid,
          senderDeviceId: aliceDev.id,
          recipientBareJid: bobDev.jid,
          keys: [first.encryptedKeys[bobDev.jid]!.single],
          payload: first.ciphertext,
          commit: first.commit,
        ),
      )).payload,
      'message 0',
    );

    // libsignal keeps PreKey until the initiator sees a reply.
    final reply = await bob.onOutgoingStanza(
      Omemo2OutgoingStanza(
        recipientJids: [aliceDev.jid],
        payload: utf8.encode('ack'),
      ),
    );
    expect(
      (await alice.onIncomingStanza(
        Omemo2IncomingStanza(
          bareSenderJid: bobDev.jid,
          senderDeviceId: bobDev.id,
          recipientBareJid: aliceDev.jid,
          keys: [reply.encryptedKeys[aliceDev.jid]!.single],
          payload: reply.ciphertext,
          commit: reply.commit,
        ),
      )).payload,
      'ack',
    );

    final second = await alice.onOutgoingStanza(
      Omemo2OutgoingStanza(
        recipientJids: [bobDev.jid],
        payload: utf8.encode('message 1'),
      ),
    );
    expect(second.encryptedKeys[bobDev.jid]!.single.kex, isFalse);
    final dec = await bob.onIncomingStanza(
      Omemo2IncomingStanza(
        bareSenderJid: aliceDev.jid,
        senderDeviceId: aliceDev.id,
        recipientBareJid: bobDev.jid,
        keys: [second.encryptedKeys[bobDev.jid]!.single],
        payload: second.ciphertext,
        commit: second.commit,
      ),
    );
    expect(dec.error, isNull);
    expect(dec.payload, 'message 1');
  });

  test('KEX falls back to signed PQ prekey when OPK pool is empty', () async {
    final (alice, bob, aliceDev, bobDev) = await pair(bobPqOpk: 0);

    final enc = await alice.onOutgoingStanza(
      Omemo2OutgoingStanza(
        recipientJids: [bobDev.jid],
        payload: utf8.encode('spk only'),
      ),
    );
    final key = enc.encryptedKeys[bobDev.jid]!.single;
    final preKey = Omemo2PreKeySignalMessage.fromSerialized(
      Uint8List.fromList(key.data),
    );
    expect(preKey.kyberPreKeyId, bobDev.pqSpkId);

    final dec = await bob.onIncomingStanza(
      Omemo2IncomingStanza(
        bareSenderJid: aliceDev.jid,
        senderDeviceId: aliceDev.id,
        recipientBareJid: bobDev.jid,
        keys: [key],
        payload: enc.ciphertext,
        commit: enc.commit,
      ),
    );
    expect(dec.error, isNull);
    expect(dec.payload, 'spk only');
  });

  test('ciphertext for another device is not decrypted', () async {
    final (alice, bob, aliceDev, bobDev) = await pair();
    final eveDev = await Omemo2Device.generate(
      'eve@example.org',
      opkCount: 1,
      pqOpkCount: 1,
    );
    final eve = Omemo2Manager(
      eveDev,
      fetchDeviceList: (_) async => null,
      fetchBundle: (_, __) async => null,
    );

    final enc = await alice.onOutgoingStanza(
      Omemo2OutgoingStanza(
        recipientJids: [bobDev.jid],
        payload: utf8.encode('secret'),
      ),
    );
    final key = enc.encryptedKeys[bobDev.jid]!.single;

    final dec = await eve.onIncomingStanza(
      Omemo2IncomingStanza(
        bareSenderJid: aliceDev.jid,
        senderDeviceId: aliceDev.id,
        recipientBareJid: eveDev.jid,
        keys: [key],
        payload: enc.ciphertext,
        commit: enc.commit,
      ),
    );
    expect(dec.error, isNotNull);
    expect(dec.payload, isNull);
  });

  test(
    'strict override missing a recipient fails before crypto or commit',
    () async {
      final aliceDev = await Omemo2Device.generate(
        'alice@example.org',
        opkCount: 2,
        pqOpkCount: 1,
      );
      final bobDev = await Omemo2Device.generate(
        'bob@example.org',
        opkCount: 2,
        pqOpkCount: 1,
      );
      final bobBundle = await bobDev.toBundle();
      var bundleFetches = 0;
      var commits = 0;
      final alice = Omemo2Manager(
        aliceDev,
        fetchDeviceList: (_) async => [bobDev.id],
        fetchBundle: (_, __) async {
          bundleFetches++;
          return bobBundle;
        },
        commitDevice: (_) async => commits++,
      );

      final enc = await alice.onOutgoingStanza(
        Omemo2OutgoingStanza(
          recipientJids: [bobDev.jid],
          payload: utf8.encode('must not go out'),
          recipientDeviceIds: const <String, Set<int>>{},
        ),
      );

      expect(enc.canSend, isFalse);
      expect(enc.ciphertext, isNull);
      expect(enc.commit, isNull);
      expect(enc.encryptedKeys, isEmpty);
      expect(enc.newSessions, isEmpty);
      expect(bundleFetches, 0, reason: 'no session may be created');
      expect(commits, 0, reason: 'no partial commit on prevalidation failure');
      expect(
        enc.deviceEncryptionErrors[bobDev.jid]!.single.error,
        isA<MissingRecipientDeviceOverrideError>(),
      );
    },
  );

  test('strict empty allow-list is authoritative, not a fallback', () async {
    final aliceDev = await Omemo2Device.generate(
      'alice@example.org',
      opkCount: 2,
      pqOpkCount: 1,
    );
    final bobDev = await Omemo2Device.generate(
      'bob@example.org',
      opkCount: 2,
      pqOpkCount: 1,
    );
    final bobBundle = await bobDev.toBundle();
    var bundleFetches = 0;
    final alice = Omemo2Manager(
      aliceDev,
      fetchDeviceList: (_) async => [bobDev.id],
      fetchBundle: (_, __) async {
        bundleFetches++;
        return bobBundle;
      },
    );

    final enc = await alice.onOutgoingStanza(
      Omemo2OutgoingStanza(
        recipientJids: [bobDev.jid],
        payload: utf8.encode('nobody'),
        recipientDeviceIds: {bobDev.jid: <int>{}},
      ),
    );

    expect(enc.canSend, isFalse);
    expect(enc.encryptedKeys, isEmpty);
    expect(enc.newSessions, isEmpty);
    expect(bundleFetches, 0, reason: 'empty set must not fall back');
    expect(
      enc.deviceEncryptionErrors[bobDev.jid]!.single.error,
      isA<NoKeyMaterialAvailableError>(),
    );
  });
}
