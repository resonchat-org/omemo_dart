import 'package:libsignal/libsignal.dart' as ls;
import 'package:omemo_dart/src/omemo2/address.dart';
import 'package:omemo_dart/src/omemo2/bundle.dart';
import 'package:omemo_dart/src/omemo2/bundle_transcript.dart';
import 'package:omemo_dart/src/omemo2/device.dart';

/// Build a session from a fetched bundle. Refuses a bundle without a
/// verified hybrid identity (monocles never-downgrade).
Future<void> omemo2EstablishSession(
  Omemo2Device own,
  Omemo2PreKeyBundle bundle,
) async {
  await own.ensureStores();
  var preKeyBundle = ls.PreKeyBundle(
    registrationId: 0,
    deviceId: 1,
    preKeyId: bundle.preKeyId,
    preKeyPublic: bundle.preKeyPublicTagged,
    signedPreKeyId: bundle.signedPreKeyId,
    signedPreKeyPublic: bundle.signedPreKeyPublicTagged,
    signedPreKeySignature: bundle.signedPreKeySignature,
    identityKey: bundle.identityPublicTagged,
    kyberPreKeyId: bundle.kyberPreKeyId,
    kyberPreKeyPublic: bundle.kyberPreKeyPublicTagged,
    kyberPreKeySignature: bundle.kyberPreKeySignature,
  );

  if (!bundle.hasPqIdentity) {
    throw StateError(
      'OMEMO2 bundle for ${bundle.jid}/${bundle.deviceId} has no usable '
      'PQ identity (pq-ik/pq-sig/ik-sig) — refusing session',
    );
  }
  final kemBinding = omemo2KemBinding(
    kemSignedPreKeyId: bundle.kemSignedPreKeyId,
    kemSignedPreKeyPublic: bundle.kemSignedPreKeyPublicTagged,
    oneTime: [
      for (final k in bundle.kemOneTimeKeys)
        (id: k.id, publicKey: k.publicTagged),
    ],
  );
  final transcript = omemo2BundleTranscript(
    identityKey: bundle.identityPublicTagged,
    pqIdentityKey: bundle.pqIdentityKey!,
    signedPreKeyId: bundle.signedPreKeyId,
    signedPreKeyPublic: bundle.signedPreKeyPublicTagged,
    kemBinding: kemBinding,
  );
  final ikOk = omemo2VerifyIdentitySignature(
    identityKey: bundle.identityPublicTagged,
    message: transcript,
    signature: bundle.ikSignature!,
  );
  if (!ikOk) {
    throw StateError(
      'OMEMO2 bundle for ${bundle.jid}/${bundle.deviceId} has invalid ik-sig',
    );
  }
  preKeyBundle = preKeyBundle.withPqIdentity(
    pqIdentityKey: bundle.pqIdentityKey!,
    pqSignature: bundle.pqSignature!,
    kemBinding: kemBinding,
  );

  final builder = ls.SessionBuilder(
    localAddress: own.localAddress,
    sessionStore: own.sessionStore,
    identityKeyStore: own.identityStore,
  );
  await builder.processPreKeyBundle(
    omemo2ProtocolAddress(bundle.jid, bundle.deviceId),
    preKeyBundle,
  );
}
