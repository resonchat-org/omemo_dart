import 'dart:convert';

import 'package:meta/meta.dart';

/// Intermediary for an axolotl `<key rid="…" prekey="true"?/>` element.
@immutable
class AxolotlEncryptedKey {
  const AxolotlEncryptedKey(this.rid, this.value, this.prekey);

  final int rid;

  /// Base64 of serialized SignalMessage / PreKeySignalMessage.
  final String value;

  /// Whether this is a PreKeySignalMessage (`prekey="true"`).
  final bool prekey;

  List<int> get data => base64Decode(value);
}
