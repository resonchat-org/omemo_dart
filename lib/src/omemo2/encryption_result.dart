import 'package:meta/meta.dart';
import 'package:omemo_dart/src/common/errors.dart';
import 'package:omemo_dart/src/omemo2/encrypted_key.dart';

@immutable
class Omemo2EncryptionResult {
  const Omemo2EncryptionResult({
    required this.ciphertext,
    required this.commit,
    required this.encryptedKeys,
    required this.deviceEncryptionErrors,
    required this.newSessions,
    required this.canSend,
  });

  /// AES-GCM ciphertext ‖ tag, or null for key-transport.
  final List<int>? ciphertext;

  /// KMAC key commitment, or null for key-transport.
  final List<int>? commit;

  /// Bare JID → per-device SessionCipher-wrapped message keys.
  final Map<String, List<Omemo2EncryptedKey>> encryptedKeys;

  final Map<String, List<EncryptToJidError>> deviceEncryptionErrors;

  final Map<String, List<int>> newSessions;

  final bool canSend;
}
