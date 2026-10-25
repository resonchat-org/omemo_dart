import 'package:omemo_dart/src/omemo2/encrypted_key.dart';

/// Incoming OMEMO2 `<encrypted>` stanza (after XML parse).
class Omemo2IncomingStanza {
  const Omemo2IncomingStanza({
    required this.bareSenderJid,
    required this.senderDeviceId,
    required this.recipientBareJid,
    required this.keys,
    required this.payload,
    this.commit,
    this.isCatchup = false,
  });

  final String bareSenderJid;
  final int senderDeviceId;

  /// Our bare JID (context binding for payload AEAD).
  final String recipientBareJid;

  final List<Omemo2EncryptedKey> keys;

  /// Base64-decoded `<payload>`, or null for key-transport.
  final List<int>? payload;

  /// Base64-decoded `<commit>`, required when [payload] is present.
  final List<int>? commit;

  final bool isCatchup;
}

/// Outgoing plaintext to encrypt for one or more bare JIDs.
class Omemo2OutgoingStanza {
  const Omemo2OutgoingStanza({
    required this.recipientJids,
    required this.payload,
    this.recipientDeviceIds,
  });

  final List<String> recipientJids;

  /// UTF-8 body bytes, or null for key-transport.
  final List<int>? payload;

  /// Per-JID device allow-list for this send.
  ///
  /// `null` keeps the legacy behavior: [Omemo2Manager.getDevicesFor] decides.
  /// A non-null map is authoritative: every [recipientJids] entry must have a
  /// key, and the value is the complete set of devices to encrypt to. An empty
  /// set means "none", not "fall back to the announced list".
  final Map<String, Set<int>>? recipientDeviceIds;
}
