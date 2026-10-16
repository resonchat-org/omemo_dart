import 'package:omemo_dart/src/omemo2/kmac.dart';
import 'package:test/test.dart';

void main() {
  // NIST SP 800-185 §A.2 KMAC256 sample #1 (S empty, L = 256).
  test('KMAC256 NIST sample #1', () {
    final key = [for (var i = 0x40; i <= 0x5f; i++) i];
    final out = kmac256(
      key: key,
      data: const [0x00, 0x01, 0x02, 0x03],
      lengthBits: 256,
      customization: '',
    );
    expect(
      out.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
      '0d5e66feaf7bad9144a42df7302e5284350a4bcd93c7f843f5f04298548a696f',
    );
  });
}
