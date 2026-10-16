import 'dart:typed_data';

import 'package:omemo_dart/omemo_dart_omemo2.dart';
import 'package:test/test.dart';

void main() {
  test('serializeMlKem1024PublicKey prefixes 0x0A', () {
    final raw = Uint8List(omemo2MlKemPublicKeyLength);
    final tagged = serializeMlKem1024PublicKey(raw);
    expect(tagged.first, omemo2MlKem1024Tag);
    expect(tagged.length, 1 + omemo2MlKemPublicKeyLength);
    expect(parseMlKem1024PublicKey(tagged), raw);
  });

  test('parseMlKem1024PublicKey refuses Round-3 Kyber tag 0x08', () {
    final bad = Uint8List.fromList([
      omemo2Kyber1024Round3Tag,
      ...List<int>.filled(omemo2MlKemPublicKeyLength, 0),
    ]);
    expect(
      () => parseMlKem1024PublicKey(bad),
      throwsA(isA<Omemo2KemException>()),
    );
  });
}
