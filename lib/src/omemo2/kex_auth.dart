import 'dart:convert';
import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:pointycastle/digests/sha3.dart';

/// Domain-separation label for handshake authentication (proto-XEP §4.9.7).
const String omemo2KexAuthLabel = 'monocles:omemo2:kex-auth:v1';

/// Algorithm fixed for `<pq-auth>` / bundle hybrid identity.
const String omemo2KexAuthAlgorithm = 'ML-DSA-87';

/// One `<key kex='true'>` as it appears in the header for the transcript.
///
/// [jid] is the `<keys jid>` attribute with only a resource stripped — not
/// re-normalised as a JID. Lower-casing happens inside [omemo2KexAuthTranscript].
class Omemo2KexAuthEntry {
  Omemo2KexAuthEntry({
    required this.jid,
    required this.rid,
    required this.keyBytes,
  });

  final String jid;
  final int rid;

  /// Decoded `<key>` content (PreKeySignalMessage bytes).
  final Uint8List keyBytes;

  /// SHA3-512 of [keyBytes] (64 bytes) — the DIGEST field of the transcript.
  Uint8List get digest {
    final d = SHA3Digest(512)..update(keyBytes, 0, keyBytes.length);
    final out = Uint8List(64);
    d.doFinal(out, 0);
    return out;
  }
}

/// Handshake transcript signed by both identity keys under `<pq-auth>`.
///
/// Byte layout matches monocles `PqAuth.transcript` / Rust
/// `pq_kex_auth_transcript` (proto-XEP §4.9.7).
Uint8List omemo2KexAuthTranscript({
  required String senderBareJid,
  required int sid,
  required List<int> identityKey,
  required List<int> pqIdentityKey,
  required List<Omemo2KexAuthEntry> entries,
}) {
  final alg = utf8.encode(omemo2KexAuthAlgorithm);
  final sender = utf8.encode(senderBareJid.toLowerCase());
  final sorted = List<Omemo2KexAuthEntry>.from(entries)
    ..sort(_compareKexEntries);

  final out = BytesBuilder(copy: false);
  out.add(utf8.encode(omemo2KexAuthLabel));
  _pushLenPrefixed(out, alg);
  _pushLenPrefixed(out, sender);
  out.add(_u32be(sid));
  _pushLenPrefixed(out, identityKey);
  _pushLenPrefixed(out, pqIdentityKey);
  out.add(_u32be(sorted.length));
  for (final e in sorted) {
    final jidBytes = utf8.encode(e.jid.toLowerCase());
    final digest = e.digest;
    _pushLenPrefixed(out, jidBytes);
    out.add(_u32be(e.rid));
    out.add(_u32be(digest.length));
    out.add(digest);
  }
  return out.toBytes();
}

/// SHA3-512 hex of [omemo2KexAuthTranscript] — used by known-answer tests.
String omemo2KexAuthTranscriptDigestHex({
  required String senderBareJid,
  required int sid,
  required List<int> identityKey,
  required List<int> pqIdentityKey,
  required List<Omemo2KexAuthEntry> entries,
}) {
  final transcript = omemo2KexAuthTranscript(
    senderBareJid: senderBareJid,
    sid: sid,
    identityKey: identityKey,
    pqIdentityKey: pqIdentityKey,
    entries: entries,
  );
  final d = SHA3Digest(512);
  d.update(transcript, 0, transcript.length);
  final out = Uint8List(64);
  d.doFinal(out, 0);
  return HEX.encode(out);
}

int _compareKexEntries(Omemo2KexAuthEntry a, Omemo2KexAuthEntry b) {
  final ja = utf8.encode(a.jid.toLowerCase());
  final jb = utf8.encode(b.jid.toLowerCase());
  final jCmp = _compareBytes(ja, jb);
  if (jCmp != 0) return jCmp;
  if (a.rid != b.rid) return a.rid.compareTo(b.rid);
  return _compareBytes(a.digest, b.digest);
}

int _compareBytes(List<int> a, List<int> b) {
  final n = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < n; i++) {
    final c = a[i].compareTo(b[i]);
    if (c != 0) return c;
  }
  return a.length.compareTo(b.length);
}

void _pushLenPrefixed(BytesBuilder out, List<int> bytes) {
  out
    ..add(_u32be(bytes.length))
    ..add(bytes);
}

Uint8List _u32be(int value) {
  final data = ByteData(4)..setUint32(0, value, Endian.big);
  return data.buffer.asUint8List();
}
