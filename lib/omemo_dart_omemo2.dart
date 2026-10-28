/// OMEMO2 / monocles PQ-OMEMO stack (`urn:monocles:omemo-pq:1`).
///
/// Session crypto uses native `package:libsignal` (PQXDH + SessionCipher +
/// SPQR). Prefer the ResonChat path fork `packages/libsignal_dart` (ML-KEM-1024
/// / wire tag `0x0A`). Linking libsignal is **AGPL-3.0**.
///
/// Interaction boundary matches `AxolotlOmemoManager`:
/// `Omemo2Manager.onOutgoingStanza` / `Omemo2Manager.onIncomingStanza`.
library omemo_dart_omemo2;

export 'package:omemo_dart/src/common/errors.dart';
export 'package:omemo_dart/src/omemo2/address.dart';
export 'package:omemo_dart/src/omemo2/bootstrap.dart';
export 'package:omemo_dart/src/omemo2/bundle.dart';
export 'package:omemo_dart/src/omemo2/bundle_transcript.dart'
    show
        Omemo2KemOneTime,
        omemo2CheckSignatures,
        omemo2VerifyIdentitySignature,
        omemo2VerifyMlDsa;
export 'package:omemo_dart/src/omemo2/constants.dart';
export 'package:omemo_dart/src/omemo2/decryption_result.dart';
export 'package:omemo_dart/src/omemo2/device.dart';
export 'package:omemo_dart/src/omemo2/encrypted_key.dart';
export 'package:omemo_dart/src/omemo2/encryption_result.dart';
export 'package:omemo_dart/src/omemo2/errors.dart';
export 'package:omemo_dart/src/omemo2/fingerprint.dart';
export 'package:omemo_dart/src/omemo2/kem_tag.dart';
export 'package:omemo_dart/src/omemo2/kex_auth.dart';
export 'package:omemo_dart/src/omemo2/manager.dart';
export 'package:omemo_dart/src/omemo2/payload.dart';
export 'package:omemo_dart/src/omemo2/stanza.dart';
export 'package:omemo_dart/src/omemo2/wire.dart';
