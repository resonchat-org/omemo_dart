/// OMEMO 0.3.0 / Conversations axolotl stack.
///
/// Wire format: `eu.siacs.conversations.axolotl` with AES-128-GCM
/// (auth-tag-in-key) and libsignal PreKeySignalMessage / SignalMessage.
///
/// Shares `package:omemo_dart/omemo_dart.dart` helpers/errors with OMEMO2.
library omemo_dart_axolotl;

export 'package:omemo_dart/src/axolotl/bundle.dart';
export 'package:omemo_dart/src/axolotl/constants.dart';
export 'package:omemo_dart/src/axolotl/crypto.dart';
export 'package:omemo_dart/src/axolotl/decryption_result.dart';
export 'package:omemo_dart/src/axolotl/device.dart';
export 'package:omemo_dart/src/axolotl/encrypted_key.dart';
export 'package:omemo_dart/src/axolotl/encryption_result.dart';
export 'package:omemo_dart/src/axolotl/fingerprint.dart';
export 'package:omemo_dart/src/axolotl/manager.dart';
export 'package:omemo_dart/src/axolotl/stanza.dart';
