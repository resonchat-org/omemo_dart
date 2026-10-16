import 'package:omemo_dart/src/axolotl/encrypted_key.dart';

/// Incoming axolotl `<encrypted>` stanza (after XML parse).
class AxolotlIncomingStanza {
  const AxolotlIncomingStanza({
    required this.bareSenderJid,
    required this.senderDeviceId,
    required this.keys,
    required this.iv,
    required this.payload,
    this.isCatchup = false,
  });

  final String bareSenderJid;
  final int senderDeviceId;

  /// Keys addressed to our device (already filtered by rid by the caller,
  /// or the full list — manager tries matching rid).
  final List<AxolotlEncryptedKey> keys;

  /// Base64-decoded `<iv>`, or null when absent.
  final List<int>? iv;

  /// Base64-decoded `<payload>`, or null for key-transport.
  final List<int>? payload;

  final bool isCatchup;
}

/// Outgoing plaintext to encrypt for one or more bare JIDs.
class AxolotlOutgoingStanza {
  const AxolotlOutgoingStanza({
    required this.recipientJids,
    required this.payload,
  });

  final List<String> recipientJids;

  /// UTF-8 body bytes, or null for key-transport / empty OMEMO.
  final List<int>? payload;
}
