import 'dart:io';

import 'package:path/path.dart' as p;

/// Prefer the ResonChat `packages/libsignal_dart` ML-KEM-1024 (0x0A) fork `.so`
/// when present next to the working tree.
String? resolveLibSignalLibraryPath() {
  final candidates = <String>[
    p.normalize(
      p.join(
        Directory.current.path,
        '..',
        'packages',
        'libsignal_dart',
        'rust',
        'target',
        'release',
        'liblibsignal_frb.so',
      ),
    ),
    p.normalize(
      p.join(
        Directory.current.path,
        'packages',
        'libsignal_dart',
        'rust',
        'target',
        'release',
        'liblibsignal_frb.so',
      ),
    ),
  ];
  for (final c in candidates) {
    if (File(c).existsSync()) return c;
  }
  return null;
}
