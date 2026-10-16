import 'package:hex/hex.dart';
import 'package:libsignal_protocol_dart/libsignal_protocol_dart.dart';

/// Conversations fingerprint: hex of the full 33-byte identity public key
/// (including the `0x05` Curve type byte) → 66 hex characters.
String axolotlFingerprint(IdentityKey identityKey) {
  return HEX.encode(identityKey.serialize());
}
