import 'dart:convert';

import 'package:meta/meta.dart';

/// Intermediary for an OMEMO2 `<key rid="…" kex="true"?/>` element.
@immutable
class Omemo2EncryptedKey {
  const Omemo2EncryptedKey(this.rid, this.value, this.kex);

  final int rid;

  /// Base64 of serialized PreKeySignalMessage / SignalMessage.
  final String value;

  /// Whether this is a PreKeySignalMessage (`kex="true"`).
  final bool kex;

  List<int> get data => base64Decode(value);
}
