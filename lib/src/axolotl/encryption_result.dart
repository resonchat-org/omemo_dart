import 'package:meta/meta.dart';
import 'package:omemo_dart/src/axolotl/encrypted_key.dart';
import 'package:omemo_dart/src/common/errors.dart';

@immutable
class AxolotlEncryptionResult {
  const AxolotlEncryptionResult({
    required this.ciphertext,
    required this.iv,
    required this.encryptedKeys,
    required this.deviceEncryptionErrors,
    required this.newSessions,
    required this.canSend,
  });

  /// AES-GCM ciphertext without tag, or null for key-transport.
  final List<int>? ciphertext;

  /// 12-byte IV for `<iv>` (null when key-transport / no payload).
  final List<int>? iv;

  /// Bare JID → per-device Signal-wrapped keys (flat list, no `<keys jid>`).
  final Map<String, List<AxolotlEncryptedKey>> encryptedKeys;

  final Map<String, List<EncryptToJidError>> deviceEncryptionErrors;

  /// JIDs for which a new Signal session was built during this encrypt.
  final Map<String, List<int>> newSessions;

  final bool canSend;
}
