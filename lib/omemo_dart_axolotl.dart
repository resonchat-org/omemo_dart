/// OMEMO 0.3.0 / Conversations axolotl stack.
///
/// Wire format: `eu.siacs.conversations.axolotl` with AES-128-GCM
/// (auth-tag-in-key) and libsignal PreKeySignalMessage / SignalMessage.
///
/// Shares `package:omemo_dart/omemo_dart.dart` helpers/errors with OMEMO2.
library omemo_dart_axolotl;

export 'src/axolotl/bundle.dart';
export 'src/axolotl/constants.dart';
export 'src/axolotl/crypto.dart';
export 'src/axolotl/decryption_result.dart';
export 'src/axolotl/device.dart';
export 'src/axolotl/encrypted_key.dart';
export 'src/axolotl/encryption_result.dart';
export 'src/axolotl/fingerprint.dart';
export 'src/axolotl/manager.dart';
export 'src/axolotl/stanza.dart';
