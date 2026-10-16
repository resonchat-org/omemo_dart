import 'dart:convert';

import 'package:logging/logging.dart';
import 'package:omemo_dart/omemo_dart_omemo2.dart';

Future<void> main() async {
  Logger.root.level = Level.ALL;
  Logger.root.onRecord.listen((r) => print(r));

  await omemo2EnsureLibSignal();

  final aliceDev = await Omemo2Device.generate('alice@example.org');
  final bobDev = await Omemo2Device.generate('bob@example.org');
  final bobBundle = await bobDev.toBundle();

  final alice = Omemo2Manager(
    aliceDev,
    fetchDeviceList: (jid) async => jid == bobDev.jid ? [bobDev.id] : null,
    fetchBundle: (jid, id) async =>
        jid == bobDev.jid && id == bobDev.id ? bobBundle : null,
  );
  final bob = Omemo2Manager(
    bobDev,
    fetchDeviceList: (_) async => null,
    fetchBundle: (_, __) async => null,
  );

  await alice.onDeviceListUpdate(bobDev.jid, [bobDev.id]);

  final enc = await alice.onOutgoingStanza(
    Omemo2OutgoingStanza(
      recipientJids: [bobDev.jid],
      payload: utf8.encode('Hello from OMEMO2'),
    ),
  );
  print('canSend=${enc.canSend} keys=${enc.encryptedKeys}');

  final key = enc.encryptedKeys[bobDev.jid]!.single;
  final dec = await bob.onIncomingStanza(
    Omemo2IncomingStanza(
      bareSenderJid: aliceDev.jid,
      senderDeviceId: aliceDev.id,
      recipientBareJid: bobDev.jid,
      keys: [key],
      payload: enc.ciphertext,
      commit: enc.commit,
    ),
  );
  print('decrypted: ${dec.payload}');
}
