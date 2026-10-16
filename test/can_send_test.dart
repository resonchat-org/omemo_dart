import 'package:omemo_dart/omemo_dart.dart';
import 'package:test/test.dart';

void main() {
  const peer = 'peer@example.org';
  const mine = 'me@example.org';

  EncryptToJidError failure([int? device]) =>
      EncryptToJidError(device, const NoKeyMaterialAvailableError());

  bool canSend(
    List<String> recipients,
    Map<String, int> successes, [
    Map<String, List<EncryptToJidError>> errors = const {},
  ]) => canSendAllDevicesReached(recipients, successes, errors);

  group('not sendable', () {
    test('no recipients', () {
      expect(canSend(const [], {}), isFalse);
    });

    test('recipient reached zero times', () {
      expect(canSend([peer], {peer: 0}), isFalse);
    });

    test('recipient missing from counts', () {
      expect(canSend([peer], {mine: 3}), isFalse);
    });

    test('partial device failures refuse the stanza', () {
      expect(
        canSend([peer], {peer: 39}, {
          peer: [failure(40)],
        }),
        isFalse,
      );
      expect(
        canSend([peer, mine], {peer: 2, mine: 1}, {
          mine: [failure(7)],
        }),
        isFalse,
      );
    });
  });

  group('sendable', () {
    test('one or many devices with no errors', () {
      expect(canSend([peer], {peer: 1}), isTrue);
      expect(canSend([peer], {peer: 40}), isTrue);
      expect(canSend([peer, mine], {peer: 2, mine: 1}), isTrue);
    });
  });
}
