// Copyright (C) 2026 ResonChat contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// XEP-0420 SCE envelope for OMEMO2 payloads (monocles proto-XEP §4.6).
// Built before AEAD seal / parsed after AEAD open — part of the OMEMO2
// crypto profile, not of the XMPP stanza layer.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

/// SCE envelope namespace (XEP-0420).
const String omemo2SceXmlns = 'urn:xmpp:sce:1';

/// jabber:client body inside SCE `<content>`.
const String omemo2SceBodyXmlns = 'jabber:client';

/// ±7 days — monocles `MAX_TIME_SKEW_MS`.
const Duration omemo2SceMaxTimeSkew = Duration(days: 7);

const int _padBucket = 256;
const int _rpadElementOverhead = '<rpad></rpad>'.length;

const String _rpadAlphabet =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/// Parsed SCE cleartext after AEAD open.
class Omemo2SceContent {
  const Omemo2SceContent({
    required this.body,
    required this.fromJid,
    required this.toJid,
    required this.time,
  });

  /// Cleartext body, or empty when the envelope had no `<body>`.
  final String body;
  final String fromJid;
  final String toJid;
  final DateTime time;
}

/// Padmé (Nikitin et al.) then round up to [PAD_BUCKET] — monocles
/// `paddedEnvelopeLength`.
int omemo2PaddedEnvelopeLength(int unpadded) {
  final x = unpadded + 1;
  final e = x == 0 ? 0 : (x.bitLength - 1); // floor(log2 x)
  // floor(log2 e) + 1, or 0 when e == 0 (matches Java numberOfLeadingZeros).
  final s = e == 0 ? 0 : e.bitLength;
  final shift = e - s;
  final mask = shift <= 0 ? 0 : ((1 << shift) - 1);
  final padme = (x + mask) & ~mask;
  return ((padme + _padBucket - 1) ~/ _padBucket) * _padBucket;
}

String _generateRpad(int length) {
  final rnd = Random.secure();
  final sb = StringBuffer();
  for (var i = 0; i < length; i++) {
    sb.write(_rpadAlphabet[rnd.nextInt(_rpadAlphabet.length)]);
  }
  return sb.toString();
}

String _xmlEscape(String s) {
  // Match monocles XmlHelper.encodeEntities (incl. stripping most C0 controls).
  final stripped = s.replaceAll(
    RegExp(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]'),
    '',
  );
  return stripped
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&apos;');
}

String _isoUtcSecond(DateTime t) {
  final u = t.toUtc();
  String two(int n) => n.toString().padLeft(2, '0');
  return '${u.year.toString().padLeft(4, '0')}-'
      '${two(u.month)}-${two(u.day)}T'
      '${two(u.hour)}:${two(u.minute)}:${two(u.second)}Z';
}

DateTime? _parseIsoTimestamp(String stamp) {
  // XEP-0082 DateTime: date, 'T', time with seconds, optional fraction,
  // mandatory zone ('Z' or ±HH:MM). Refuse date-only / missing zone.
  if (stamp.length < 20 || stamp[10] != 'T') return null;
  final zoned =
      stamp.endsWith('Z') ||
      stamp.endsWith('z') ||
      stamp.lastIndexOf('+') > 18 ||
      stamp.lastIndexOf('-') > 18;
  if (!zoned) return null;
  try {
    return DateTime.parse(stamp).toUtc();
  } catch (_) {
    return null;
  }
}

String _bare(String jid) {
  final slash = jid.indexOf('/');
  final bare = (slash < 0 ? jid : jid.substring(0, slash)).trim();
  return bare.toLowerCase();
}

/// Build a monocles-shaped SCE envelope UTF-8 bytes for AEAD plaintext.
///
/// Affix order matches monocles `buildSceEnvelope`: content, time, from, to,
/// then sized `<rpad>`. Attribute quotes are double (Conversations Tag).
Uint8List omemo2BuildSceEnvelope({
  required String? body,
  required String senderBareJid,
  required String recipientBareJid,
  DateTime? timestamp,
}) {
  final from = _bare(senderBareJid);
  final to = _bare(recipientBareJid);
  final stamp = _isoUtcSecond(timestamp ?? DateTime.now().toUtc());

  final contentKids = StringBuffer();
  if (body != null && body.isNotEmpty) {
    contentKids.write(
      '<body xmlns="$omemo2SceBodyXmlns">${_xmlEscape(body)}</body>',
    );
  }

  // Unpadded = envelope without <rpad>, plus empty <rpad></rpad> overhead.
  final withoutRpad =
      '<envelope xmlns="$omemo2SceXmlns">'
      '<content>$contentKids</content>'
      '<time stamp="$stamp"/>'
      '<from jid="${_xmlEscape(from)}"/>'
      '<to jid="${_xmlEscape(to)}"/>'
      '</envelope>';
  final unpadded = utf8.encode(withoutRpad).length + _rpadElementOverhead;
  final target = omemo2PaddedEnvelopeLength(unpadded);
  final padLen = target - unpadded;
  if (padLen < 1) {
    throw StateError('OMEMO2 SCE rpad length must be >= 1 (got $padLen)');
  }
  final rpad = _generateRpad(padLen);
  final xml =
      '<envelope xmlns="$omemo2SceXmlns">'
      '<content>$contentKids</content>'
      '<time stamp="$stamp"/>'
      '<from jid="${_xmlEscape(from)}"/>'
      '<to jid="${_xmlEscape(to)}"/>'
      '<rpad>$rpad</rpad>'
      '</envelope>';
  final bytes = Uint8List.fromList(utf8.encode(xml));
  if (bytes.length != target) {
    throw StateError(
      'OMEMO2 SCE padding miss: got ${bytes.length}, want $target',
    );
  }
  return bytes;
}

bool _isServerProcessed({required String name, required String? xmlns}) {
  if (xmlns == 'urn:xmpp:hints') return true;
  if (xmlns == 'urn:xmpp:sid:0' &&
      (name == 'stanza-id' || name == 'origin-id')) {
    return true;
  }
  if (xmlns == 'http://jabber.org/protocol/address') return true;
  return xmlns == 'urn:xmpp:eme:0' && name == 'encryption';
}

/// Parse and verify SCE affixes after AEAD open (monocles `parseSceContent`).
Omemo2SceContent omemo2ParseSceEnvelope(
  List<int> plaintext, {
  required String expectedFromBareJid,
  required String expectedToBareJid,
  DateTime? stanzaTimestamp,
  DateTime? now,
}) {
  final xml = utf8.decode(plaintext);
  final envelope = _findElement(xml, 'envelope');
  if (envelope == null) {
    throw StateError('no SCE <envelope> found in plaintext');
  }
  final envXmlns = _attr(envelope.openTag, 'xmlns');
  if (envXmlns != null && envXmlns != omemo2SceXmlns) {
    throw StateError('SCE envelope xmlns mismatch: $envXmlns');
  }

  final content = _findElement(envelope.inner, 'content');
  if (content == null) {
    throw StateError('SCE envelope missing <content>');
  }

  final fromEl = _findElement(envelope.inner, 'from');
  final toEl = _findElement(envelope.inner, 'to');
  final timeEl = _findElement(envelope.inner, 'time');
  if (fromEl == null) throw StateError('SCE envelope missing <from>');
  if (toEl == null) throw StateError('SCE envelope missing <to>');
  if (timeEl == null) {
    throw StateError('SCE envelope missing required <time>');
  }

  final fromJid = _attr(fromEl.openTag, 'jid');
  final toJid = _attr(toEl.openTag, 'jid');
  final stamp = _attr(timeEl.openTag, 'stamp');
  if (fromJid == null) throw StateError('SCE <from> missing jid attribute');
  if (toJid == null) throw StateError('SCE <to> missing jid attribute');
  if (stamp == null) throw StateError('SCE <time> missing stamp attribute');

  final wantFrom = _bare(expectedFromBareJid);
  final wantTo = _bare(expectedToBareJid);
  final gotFrom = _bare(fromJid);
  final gotTo = _bare(toJid);
  if (gotFrom != wantFrom) {
    throw StateError('SCE <from> mismatch: expected $wantFrom got $gotFrom');
  }
  if (gotTo != wantTo) {
    throw StateError('SCE <to> mismatch: expected $wantTo got $gotTo');
  }

  final ts = _parseIsoTimestamp(stamp);
  if (ts == null) {
    throw StateError('SCE <time> unparseable stamp: $stamp');
  }
  final clock = (now ?? DateTime.now()).toUtc();
  if (ts.difference(clock) > omemo2SceMaxTimeSkew) {
    throw StateError('SCE <time> too far in the future: $stamp');
  }
  final reference = (stanzaTimestamp ?? clock).toUtc();
  if (ts.difference(reference).abs() > omemo2SceMaxTimeSkew) {
    throw StateError(
      'SCE <time> ($stamp) inconsistent with stanza sending time — '
      'possible replay',
    );
  }

  var body = '';
  for (final child in _directChildren(content.inner)) {
    final name = child.localName;
    final xmlns = _attr(child.openTag, 'xmlns');
    if (_isServerProcessed(name: name, xmlns: xmlns)) continue;
    if (name == 'body') {
      body = _xmlUnescape(child.inner);
    }
  }

  return Omemo2SceContent(body: body, fromJid: gotFrom, toJid: gotTo, time: ts);
}

// --- minimal XML helpers for the fixed SCE shape ---

class _El {
  const _El({
    required this.localName,
    required this.openTag,
    required this.inner,
    required this.end,
  });
  final String localName;
  final String openTag;
  final String inner;

  /// Index just past this element in the haystack it was found in.
  final int end;
}

String? _attr(String openTag, String name) {
  final re = RegExp(
    '$name\\s*=\\s*"([^"]*)"|$name\\s*=\\s*\'([^\']*)\'',
    caseSensitive: false,
  );
  final m = re.firstMatch(openTag);
  if (m == null) return null;
  return _xmlUnescape(m.group(1) ?? m.group(2) ?? '');
}

String _xmlUnescape(String s) => s
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&quot;', '"')
    .replaceAll('&apos;', "'")
    .replaceAll('&amp;', '&');

_El? _findElement(String haystack, String local, {int from = 0}) {
  final openRe = RegExp('<$local(?=[\\s>/])');
  final m = openRe.firstMatch(haystack.substring(from));
  if (m == null) return null;
  final start = from + m.start;
  final gt = haystack.indexOf('>', start);
  if (gt < 0) return null;
  final openTag = haystack.substring(start, gt + 1);
  if (openTag.endsWith('/>')) {
    return _El(localName: local, openTag: openTag, inner: '', end: gt + 1);
  }
  final close = '</$local>';
  var depth = 1;
  var i = gt + 1;
  while (i < haystack.length && depth > 0) {
    final rest = haystack.substring(i);
    final nextOpenRel = RegExp('<$local(?=[\\s>/])').firstMatch(rest);
    final nextClose = haystack.indexOf(close, i);
    if (nextClose < 0) return null;
    final nextOpen = nextOpenRel == null ? -1 : i + nextOpenRel.start;
    if (nextOpen >= 0 && nextOpen < nextClose) {
      final openEnd = haystack.indexOf('>', nextOpen);
      if (openEnd < 0) return null;
      final tag = haystack.substring(nextOpen, openEnd + 1);
      if (!tag.endsWith('/>')) depth++;
      i = openEnd + 1;
      continue;
    }
    depth--;
    if (depth == 0) {
      return _El(
        localName: local,
        openTag: openTag,
        inner: haystack.substring(gt + 1, nextClose),
        end: nextClose + close.length,
      );
    }
    i = nextClose + close.length;
  }
  return null;
}

List<_El> _directChildren(String inner) {
  final out = <_El>[];
  var i = 0;
  while (i < inner.length) {
    while (i < inner.length && inner.codeUnitAt(i) <= 0x20) {
      i++;
    }
    if (i >= inner.length || inner[i] != '<') break;
    if (inner.startsWith('</', i)) break;
    final nameMatch = RegExp(
      r'^<\s*([A-Za-z0-9:_\-]+)',
    ).firstMatch(inner.substring(i));
    if (nameMatch == null) break;
    final rawName = nameMatch.group(1)!;
    final local = rawName.contains(':')
        ? rawName.substring(rawName.indexOf(':') + 1)
        : rawName;
    final el = _findElement(inner, local, from: i);
    if (el == null) break;
    out.add(el);
    i = el.end;
  }
  return out;
}
