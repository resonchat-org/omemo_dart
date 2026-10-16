import 'package:libsignal/libsignal.dart';
import 'package:omemo_dart/src/omemo2/bootstrap_path_stub.dart'
    if (dart.library.io) 'package:omemo_dart/src/omemo2/bootstrap_path_io.dart'
    as path_probe;

/// Ensures [LibSignal.init] has run in this isolate.
///
/// On native platforms, prefers a local `liblibsignal_frb.so` from the
/// ResonChat `packages/libsignal_dart` ML-KEM-1024 (0x0A) fork when present.
/// On web, [libraryPath] is ignored and flutter_rust_bridge loads the WASM
/// module from its default location.
Future<void> omemo2EnsureLibSignal({String? libraryPath}) async {
  if (LibSignal.isInitialized) return;

  final path = libraryPath ?? path_probe.resolveLibSignalLibraryPath();
  await LibSignal.init(libraryPath: path);
}
