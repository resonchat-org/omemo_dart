import 'package:meta/meta.dart';

import 'package:omemo_dart/src/common/errors.dart';

@immutable
class Omemo2DecryptionResult {
  const Omemo2DecryptionResult({
    required this.payload,
    required this.newSessions,
    required this.error,
  });

  /// Decrypted UTF-8 body, or null for key-transport / failure.
  final String? payload;

  final Map<String, List<int>> newSessions;

  final OmemoError? error;
}
