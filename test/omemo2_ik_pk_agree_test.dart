import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:libsignal/libsignal.dart' as ls;
import 'package:test/test.dart';

import 'package:omemo_dart/src/common/keys.dart';
import 'package:omemo_dart/src/omemo2/bootstrap.dart';
import 'package:omemo_dart/src/omemo2/device.dart';

void main() {
  setUpAll(omemo2EnsureLibSignal);

  test(
    'published ikDh.pk matches libsignal IdentityKey from same sk',
    () async {
      final ikEd = await OmemoKeyPair.generateNewPair(KeyPairType.ed25519);
      final ik = await ikEd.toCurve25519();
      final sk = Uint8List.fromList(await ik.sk.getBytes());
      final pkCrypto = Uint8List.fromList(await ik.pk.getBytes());

      final idPair = ls.IdentityKeyPair.fromKeys(
        privateKey: ls.PrivateKey.deserialize(bytes: sk),
        publicKey: ls.PrivateKey.deserialize(bytes: sk).getPublicKey(),
      );
      final pkLib = idPair.publicKey; // 0x05 ‖ 32
      expect(pkLib.length, 33);
      expect(pkLib.first, 0x05);
      expect(
        pkCrypto,
        pkLib.sublist(1),
        reason:
            'Bundle publishes cryptography X25519 pk; fingerprint uses '
            'libsignal-derived IdentityKey — they must be identical',
      );
    },
  );

  test('Omemo2Device.identityPublicSerialized matches toBundle ik', () async {
    final device = await Omemo2Device.generate(
      'alice@example.org',
      opkCount: 1,
      pqOpkCount: 1,
    );
    final serialized = await device.identityPublicSerialized();
    final bundle = await device.toBundle();
    expect(serialized, bundle.identityPublicTagged);
  });
}
