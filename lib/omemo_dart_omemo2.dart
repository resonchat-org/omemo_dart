/// OMEMO2 / monocles PQ-OMEMO stack (`urn:monocles:omemo-pq:1`).
///
/// Session crypto uses native `package:libsignal` (PQXDH + SessionCipher +
/// SPQR). Prefer the ResonChat path fork `packages/libsignal_dart` (ML-KEM-1024
/// / wire tag `0x0A`). Linking libsignal is **AGPL-3.0**.
///
/// Interaction boundary matches `AxolotlOmemoManager`:
/// `Omemo2Manager.onOutgoingStanza` / `Omemo2Manager.onIncomingStanza`.
library omemo_dart_omemo2;

export 'src/omemo2/address.dart';
export 'src/omemo2/bootstrap.dart';
export 'src/omemo2/bundle.dart';
export 'src/omemo2/bundle_transcript.dart'
    show Omemo2KemOneTime, omemo2CheckSignatures;
export 'src/omemo2/constants.dart';
export 'src/omemo2/decryption_result.dart';
export 'src/omemo2/device.dart';
export 'src/omemo2/encrypted_key.dart';
export 'src/omemo2/encryption_result.dart';
export 'src/omemo2/errors.dart';
export 'src/omemo2/fingerprint.dart';
export 'src/omemo2/kem_tag.dart';
export 'src/omemo2/manager.dart';
export 'src/omemo2/payload.dart';
export 'src/omemo2/stanza.dart';
export 'src/omemo2/wire.dart';
