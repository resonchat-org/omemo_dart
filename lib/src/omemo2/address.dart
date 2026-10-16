import 'package:libsignal/libsignal.dart';

/// Map an OMEMO (jid, deviceId) onto a libsignal [ProtocolAddress].
///
/// libsignal rejects device ids outside 1–127; OMEMO publishes 31-bit ids.
/// Encode the real device id in the address name and pin Signal's device id
/// to 1 so PQXDH/SessionCipher accept the address without truncating the
/// OMEMO id that appears on PEP / `<key>`.
ProtocolAddress omemo2ProtocolAddress(String jid, int deviceId) =>
    ProtocolAddress(name: '$jid#$deviceId', deviceId: 1);
