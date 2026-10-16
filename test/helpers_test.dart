import 'package:omemo_dart/omemo_dart.dart';
import 'package:test/test.dart';

void main() {
  test('generateRandomOmemoId never returns 0', () {
    for (var i = 0; i < 200; i++) {
      final id = generateRandomOmemoId();
      expect(id, greaterThan(0));
      expect(id, lessThan(0x7FFFFFFF));
    }
  });
}
