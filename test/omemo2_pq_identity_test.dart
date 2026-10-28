import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import 'package:omemo_dart/omemo_dart_omemo2.dart';

void main() {
  setUpAll(() async {
    await omemo2EnsureLibSignal();
  });

  test('withPqIdentity rejects a tampered pq-sig on process', () async {
    final alice = await Omemo2Device.generate('alice@ex.org', pqOpkCount: 1);
    final bob = await Omemo2Device.generate('bob@ex.org', pqOpkCount: 1);
    await bob.ensureStores();

    final pq = PqIdentityKeyPair.generate();
    final pqPub = pq.publicKey().serialize();
    final bobBundle = await bob.toBundle();

    final kemBinding = pqKemBinding(
      kemSignedPreKeyId: bobBundle.kemSignedPreKeyId,
      kemSignedPreKeyPublic: bobBundle.kemSignedPreKeyPublicTagged,
      oneTime: [
        for (final k in bobBundle.kemOneTimeKeys)
          KemOneTimeKey(id: k.id, publicKey: k.publicTagged),
      ],
    );
    final transcript = pqBundleTranscript(
      identityKey: bobBundle.identityPublicTagged,
      pqIdentityKey: pqPub,
      signedPreKeyId: bobBundle.signedPreKeyId,
      signedPreKeyPublic: bobBundle.signedPreKeyPublicTagged,
      kemBinding: kemBinding,
    );
    final goodSig = pq.sign(message: transcript).serialize();
    final badSig = Uint8List.fromList(goodSig)..[0] ^= 0xff;
    final ikSig = await bob.sign(transcript);

    final plain = PreKeyBundle(
      registrationId: 0,
      deviceId: 1,
      preKeyId: bobBundle.preKeyId,
      preKeyPublic: bobBundle.preKeyPublicTagged,
      signedPreKeyId: bobBundle.signedPreKeyId,
      signedPreKeyPublic: bobBundle.signedPreKeyPublicTagged,
      signedPreKeySignature: bobBundle.signedPreKeySignature,
      identityKey: bobBundle.identityPublicTagged,
      kyberPreKeyId: bobBundle.kyberPreKeyId,
      kyberPreKeyPublic: bobBundle.kyberPreKeyPublicTagged,
      kyberPreKeySignature: bobBundle.kyberPreKeySignature,
    );

    final withBad = plain.withPqIdentity(
      pqIdentityKey: pqPub,
      pqSignature: badSig,
      kemBinding: kemBinding,
    );

    await alice.ensureStores();
    final builder = SessionBuilder(
      localAddress: alice.localAddress,
      sessionStore: alice.sessionStore,
      identityKeyStore: alice.identityStore,
    );
    await expectLater(
      builder.processPreKeyBundle(
        omemo2ProtocolAddress(bob.jid, bob.id),
        withBad,
      ),
      throwsA(isA<LibSignalException>()),
    );

    final withGood = plain.withPqIdentity(
      pqIdentityKey: pqPub,
      pqSignature: goodSig,
      kemBinding: kemBinding,
    );
    await builder.processPreKeyBundle(
      omemo2ProtocolAddress(bob.jid, bob.id),
      withGood,
    );

    // App/omemo_dart pull path also requires ik-sig on Omemo2PreKeyBundle.
    final omemo2 = Omemo2PreKeyBundle(
      jid: bobBundle.jid,
      deviceId: bobBundle.deviceId,
      identityPublicTagged: bobBundle.identityPublicTagged,
      signedPreKeyId: bobBundle.signedPreKeyId,
      signedPreKeyPublicTagged: bobBundle.signedPreKeyPublicTagged,
      signedPreKeySignature: bobBundle.signedPreKeySignature,
      kyberPreKeyId: bobBundle.kyberPreKeyId,
      kyberPreKeyPublicTagged: bobBundle.kyberPreKeyPublicTagged,
      kyberPreKeySignature: bobBundle.kyberPreKeySignature,
      kemSignedPreKeyId: bobBundle.kemSignedPreKeyId,
      kemSignedPreKeyPublicTagged: bobBundle.kemSignedPreKeyPublicTagged,
      kemOneTimeKeys: bobBundle.kemOneTimeKeys,
      preKeyId: bobBundle.preKeyId,
      preKeyPublicTagged: bobBundle.preKeyPublicTagged,
      pqIdentityKey: pqPub,
      pqSignature: goodSig,
      ikSignature: ikSig,
    );
    expect(omemo2.hasPqIdentity, isTrue);
    expect(
      PublicKey.deserialize(
        bytes: bobBundle.identityPublicTagged.toList(),
      ).verify(message: transcript.toList(), signature: ikSig.toList()),
      isTrue,
    );
  });
}
