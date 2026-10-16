import 'package:omemo_dart/src/common/errors.dart';

/// Whether an outgoing stanza may be sent: every intended recipient was
/// reached on at least one device and no device recorded an error.
bool canSendAllDevicesReached(
  List<String> recipientJids,
  Map<String, int> successfulEncryptions,
  Map<String, List<EncryptToJidError>> encryptionErrors,
) =>
    recipientJids.isNotEmpty &&
    encryptionErrors.isEmpty &&
    recipientJids.every((jid) => (successfulEncryptions[jid] ?? 0) > 0);
