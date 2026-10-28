import 'package:meta/meta.dart';

import 'package:omemo_dart/src/common/errors.dart';

@immutable
class AxolotlDecryptionResult {
  const AxolotlDecryptionResult({
    required this.payload,
    required this.newSessions,
    required this.error,
    this.usedPreKeyId,
  });

  /// Decrypted UTF-8 body, or null for key-transport / empty.
  final String? payload;

  final int? usedPreKeyId;

  final Map<String, List<int>> newSessions;

  final OmemoError? error;
}
