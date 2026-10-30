import 'dart:convert';

import 'package:test/test.dart';

import 'package:omemo_dart/omemo_dart_omemo2.dart';

void main() {
  group('omemo2PaddedEnvelopeLength', () {
    test('matches monocles Padmé + 256 bucket', () {
      // Spot-check values against the Java formula for small sizes.
      expect(omemo2PaddedEnvelopeLength(1), 256);
      expect(omemo2PaddedEnvelopeLength(200), 256);
      expect(omemo2PaddedEnvelopeLength(256), 512);
      expect(omemo2PaddedEnvelopeLength(255), 256);
      for (var n = 1; n < 4096; n += 17) {
        final padded = omemo2PaddedEnvelopeLength(n);
        expect(padded % 256, 0, reason: 'n=$n');
        expect(padded, greaterThan(n), reason: 'n=$n');
      }
    });
  });

  group('SCE envelope', () {
    test('build lands on padded size and round-trips', () {
      final bytes = omemo2BuildSceEnvelope(
        body: 'hello monocles',
        senderBareJid: 'alice@example.org',
        recipientBareJid: 'bob@example.org',
        timestamp: DateTime.utc(2026, 10, 30, 2, 0, 0),
      );
      expect(bytes.length % 256, 0);
      expect(utf8.decode(bytes), contains('<envelope xmlns="urn:xmpp:sce:1">'));
      expect(utf8.decode(bytes), contains('<rpad>'));

      final parsed = omemo2ParseSceEnvelope(
        bytes,
        expectedFromBareJid: 'alice@example.org',
        expectedToBareJid: 'bob@example.org',
        stanzaTimestamp: DateTime.utc(2026, 10, 30, 2, 0, 0),
        now: DateTime.utc(2026, 10, 30, 2, 0, 1),
      );
      expect(parsed.body, 'hello monocles');
      expect(parsed.fromJid, 'alice@example.org');
      expect(parsed.toJid, 'bob@example.org');
    });

    test('escapes body entities', () {
      final bytes = omemo2BuildSceEnvelope(
        body: 'a < b & "c"',
        senderBareJid: 'a@x',
        recipientBareJid: 'b@x',
        timestamp: DateTime.utc(2026, 1, 1),
      );
      final parsed = omemo2ParseSceEnvelope(
        bytes,
        expectedFromBareJid: 'a@x',
        expectedToBareJid: 'b@x',
        stanzaTimestamp: DateTime.utc(2026, 1, 1),
        now: DateTime.utc(2026, 1, 1),
      );
      expect(parsed.body, 'a < b & "c"');
    });

    test('rejects from mismatch', () {
      final bytes = omemo2BuildSceEnvelope(
        body: 'x',
        senderBareJid: 'alice@example.org',
        recipientBareJid: 'bob@example.org',
        timestamp: DateTime.utc(2026, 10, 30),
      );
      expect(
        () => omemo2ParseSceEnvelope(
          bytes,
          expectedFromBareJid: 'eve@example.org',
          expectedToBareJid: 'bob@example.org',
          stanzaTimestamp: DateTime.utc(2026, 10, 30),
          now: DateTime.utc(2026, 10, 30),
        ),
        throwsStateError,
      );
    });

    test('rejects missing time', () {
      const xml =
          '<envelope xmlns="urn:xmpp:sce:1">'
          '<content><body xmlns="jabber:client">x</body></content>'
          '<from jid="a@x"/>'
          '<to jid="b@x"/>'
          '<rpad>x</rpad>'
          '</envelope>';
      expect(
        () => omemo2ParseSceEnvelope(
          utf8.encode(xml),
          expectedFromBareJid: 'a@x',
          expectedToBareJid: 'b@x',
          now: DateTime.utc(2026, 10, 30),
        ),
        throwsStateError,
      );
    });

    test('rejects future time beyond skew', () {
      final bytes = omemo2BuildSceEnvelope(
        body: 'x',
        senderBareJid: 'a@x',
        recipientBareJid: 'b@x',
        timestamp: DateTime.utc(2026, 12, 1),
      );
      expect(
        () => omemo2ParseSceEnvelope(
          bytes,
          expectedFromBareJid: 'a@x',
          expectedToBareJid: 'b@x',
          stanzaTimestamp: DateTime.utc(2026, 12, 1),
          now: DateTime.utc(2026, 10, 30),
        ),
        throwsStateError,
      );
    });

    test('omits empty body', () {
      final bytes = omemo2BuildSceEnvelope(
        body: '',
        senderBareJid: 'a@x',
        recipientBareJid: 'b@x',
        timestamp: DateTime.utc(2026, 10, 30),
      );
      expect(utf8.decode(bytes), isNot(contains('<body')));
      final parsed = omemo2ParseSceEnvelope(
        bytes,
        expectedFromBareJid: 'a@x',
        expectedToBareJid: 'b@x',
        stanzaTimestamp: DateTime.utc(2026, 10, 30),
        now: DateTime.utc(2026, 10, 30),
      );
      expect(parsed.body, '');
    });

    test('parses monocles-like single-quote attributes', () {
      // Receivers must accept either quote style.
      const xml =
          "<envelope xmlns='urn:xmpp:sce:1'>"
          "<content><body xmlns='jabber:client'>hi</body></content>"
          "<time stamp='2026-10-30T02:00:00Z'/>"
          "<from jid='alice@example.org'/>"
          "<to jid='bob@example.org'/>"
          '<rpad>abc</rpad>'
          '</envelope>';
      final parsed = omemo2ParseSceEnvelope(
        utf8.encode(xml),
        expectedFromBareJid: 'alice@example.org',
        expectedToBareJid: 'bob@example.org',
        stanzaTimestamp: DateTime.utc(2026, 10, 30, 2),
        now: DateTime.utc(2026, 10, 30, 2),
      );
      expect(parsed.body, 'hi');
    });
  });
}
