import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';
import 'package:libsignal_protocol_dart/libsignal_protocol_dart.dart';
import 'package:omemo_dart/src/omemo2/constants.dart';
import 'package:omemo_dart/src/omemo2/errors.dart';

/// Minimal protobuf writer for Signal wire messages (libsignal `wire.proto`).
class _ProtoWriter {
  final BytesBuilder _out = BytesBuilder(copy: false);

  void writeBytes(int fieldNumber, List<int> value) {
    _writeTag(fieldNumber, 2);
    _writeVarint(value.length);
    _out.add(value);
  }

  void writeUint32(int fieldNumber, int value) {
    _writeTag(fieldNumber, 0);
    _writeVarint(value);
  }

  void _writeTag(int fieldNumber, int wireType) {
    _writeVarint((fieldNumber << 3) | wireType);
  }

  void _writeVarint(int value) {
    var v = value;
    while (v > 0x7f) {
      _out.addByte((v & 0x7f) | 0x80);
      v >>= 7;
    }
    _out.addByte(v);
  }

  Uint8List toBytes() => _out.toBytes();
}

class _ProtoReader {
  _ProtoReader(this._buf) : _pos = 0;

  final Uint8List _buf;
  int _pos;

  bool get isDone => _pos >= _buf.length;

  int readTag() => _readVarint();

  int fieldNumber(int tag) => tag >> 3;
  int wireType(int tag) => tag & 0x7;

  int readUint32() => _readVarint();

  Uint8List readBytes() {
    final len = _readVarint();
    if (_pos + len > _buf.length) {
      throw const Omemo2InvalidMessageException('truncated protobuf bytes');
    }
    final out = _buf.sublist(_pos, _pos + len);
    _pos += len;
    return out;
  }

  void skip(int wireType) {
    switch (wireType) {
      case 0:
        _readVarint();
      case 1:
        _pos += 8;
      case 2:
        final len = _readVarint();
        _pos += len;
      case 5:
        _pos += 4;
      default:
        throw Omemo2InvalidMessageException('unknown wire type $wireType');
    }
  }

  int _readVarint() {
    var result = 0;
    var shift = 0;
    while (_pos < _buf.length) {
      final b = _buf[_pos++];
      result |= (b & 0x7f) << shift;
      if ((b & 0x80) == 0) return result;
      shift += 7;
      if (shift > 35) {
        throw const Omemo2InvalidMessageException('varint too long');
      }
    }
    throw const Omemo2InvalidMessageException('truncated varint');
  }
}

int _versionByte(int messageVersion) =>
    ((messageVersion & 0xf) << 4) | (omemo2CiphertextMessageVersion & 0xf);

/// OMEMO2 / libsignal `SignalMessage` (version 4, optional `pq_ratchet`).
class Omemo2SignalMessage {
  Omemo2SignalMessage._({
    required this.messageVersion,
    required this.senderRatchetKey,
    required this.counter,
    required this.previousCounter,
    required this.ciphertext,
    required this.serialized,
    this.pqRatchet,
  });

  /// Build and MAC a SignalMessage (libsignal layout + optional SPQR chunk).
  factory Omemo2SignalMessage.create({
    required int messageVersion,
    required Uint8List macKey,
    required ECPublicKey senderRatchetKey,
    required int counter,
    required int previousCounter,
    required Uint8List ciphertext,
    required IdentityKey senderIdentityKey,
    required IdentityKey receiverIdentityKey,
    Uint8List? pqRatchet,
  }) {
    final version = Uint8List.fromList([_versionByte(messageVersion)]);
    final proto = _ProtoWriter()
      ..writeBytes(1, senderRatchetKey.serialize())
      ..writeUint32(2, counter)
      ..writeUint32(3, previousCounter)
      ..writeBytes(4, ciphertext);
    if (pqRatchet != null && pqRatchet.isNotEmpty) {
      proto.writeBytes(5, pqRatchet);
    }
    final body = proto.toBytes();
    final mac = _computeMac(
      senderIdentityKey,
      receiverIdentityKey,
      macKey,
      Uint8List.fromList([...version, ...body]),
    );
    final serialized = Uint8List.fromList([...version, ...body, ...mac]);
    return Omemo2SignalMessage._(
      messageVersion: messageVersion,
      senderRatchetKey: senderRatchetKey,
      counter: counter,
      previousCounter: previousCounter,
      ciphertext: ciphertext,
      pqRatchet: pqRatchet,
      serialized: serialized,
    );
  }

  factory Omemo2SignalMessage.fromSerialized(Uint8List serialized) {
    if (serialized.length < 1 + omemo2MacLength) {
      throw const Omemo2InvalidMessageException('SignalMessage too short');
    }
    final versionByte = serialized[0];
    final messageVersion = (versionByte >> 4) & 0xf;
    if (messageVersion < omemo2PreKyberCiphertextVersion) {
      throw Omemo2InvalidMessageException(
        'legacy SignalMessage version $messageVersion',
      );
    }
    if (messageVersion > omemo2CiphertextMessageVersion) {
      throw Omemo2InvalidMessageException(
        'unknown SignalMessage version $messageVersion',
      );
    }

    final protoBytes = serialized.sublist(
      1,
      serialized.length - omemo2MacLength,
    );
    final reader = _ProtoReader(protoBytes);
    Uint8List? ratchetKey;
    var counter = 0;
    var previousCounter = 0;
    Uint8List? ciphertext;
    Uint8List? pqRatchet;
    while (!reader.isDone) {
      final tag = reader.readTag();
      final fn = reader.fieldNumber(tag);
      final wt = reader.wireType(tag);
      switch (fn) {
        case 1:
          ratchetKey = reader.readBytes();
        case 2:
          counter = reader.readUint32();
        case 3:
          previousCounter = reader.readUint32();
        case 4:
          ciphertext = reader.readBytes();
        case 5:
          pqRatchet = reader.readBytes();
        default:
          reader.skip(wt);
      }
    }
    if (ratchetKey == null || ciphertext == null) {
      throw const Omemo2InvalidMessageException('incomplete SignalMessage');
    }

    return Omemo2SignalMessage._(
      messageVersion: messageVersion,
      senderRatchetKey: Curve.decodePoint(ratchetKey, 0),
      counter: counter,
      previousCounter: previousCounter,
      ciphertext: ciphertext,
      pqRatchet: pqRatchet,
      serialized: serialized,
    );
  }

  final int messageVersion;
  final ECPublicKey senderRatchetKey;
  final int counter;
  final int previousCounter;
  final Uint8List ciphertext;
  final Uint8List? pqRatchet;
  final Uint8List serialized;

  Uint8List get body => ciphertext;

  void verifyMac(
    IdentityKey senderIdentityKey,
    IdentityKey receiverIdentityKey,
    Uint8List macKey,
  ) {
    final parts = _splitMac(serialized);
    final our = _computeMac(
      senderIdentityKey,
      receiverIdentityKey,
      macKey,
      parts.$1,
    );
    if (!_constEq(our, parts.$2)) {
      throw const Omemo2InvalidMessageException('Bad Mac!');
    }
  }

  static (Uint8List, Uint8List) _splitMac(Uint8List serialized) {
    final macStart = serialized.length - omemo2MacLength;
    return (serialized.sublist(0, macStart), serialized.sublist(macStart));
  }

  static Uint8List _computeMac(
    IdentityKey sender,
    IdentityKey receiver,
    Uint8List macKey,
    Uint8List content,
  ) {
    final mac = Hmac(sha256, macKey);
    final sink = AccumulatorSink<Digest>();
    mac.startChunkedConversion(sink)
      ..add(sender.publicKey.serialize())
      ..add(receiver.publicKey.serialize())
      ..add(content)
      ..close();
    return Uint8List.fromList(
      sink.events.single.bytes.sublist(0, omemo2MacLength),
    );
  }

  static bool _constEq(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var d = 0;
    for (var i = 0; i < a.length; i++) {
      d |= a[i] ^ b[i];
    }
    return d == 0;
  }
}

/// OMEMO2 / libsignal `PreKeySignalMessage` (version 4 + Kyber fields).
class Omemo2PreKeySignalMessage {
  Omemo2PreKeySignalMessage({
    required this.messageVersion,
    required this.registrationId,
    required this.preKeyId,
    required this.signedPreKeyId,
    required this.kyberPreKeyId,
    required this.kyberCiphertextTagged,
    required this.baseKey,
    required this.identityKey,
    required this.message,
    required this.serialized,
  });

  factory Omemo2PreKeySignalMessage.create({
    required int messageVersion,
    required int registrationId,
    required int signedPreKeyId,
    required int kyberPreKeyId,
    required Uint8List kyberCiphertextTagged,
    required ECPublicKey baseKey,
    required IdentityKey identityKey,
    required Omemo2SignalMessage message,
    int? preKeyId,
  }) {
    final proto = _ProtoWriter();
    if (preKeyId != null) {
      proto.writeUint32(1, preKeyId);
    }
    proto
      ..writeBytes(2, baseKey.serialize())
      ..writeBytes(3, identityKey.serialize())
      ..writeBytes(4, message.serialized)
      ..writeUint32(5, registrationId)
      ..writeUint32(6, signedPreKeyId)
      ..writeUint32(7, kyberPreKeyId)
      ..writeBytes(8, kyberCiphertextTagged);

    final version = Uint8List.fromList([_versionByte(messageVersion)]);
    final serialized = Uint8List.fromList([...version, ...proto.toBytes()]);
    return Omemo2PreKeySignalMessage(
      messageVersion: messageVersion,
      registrationId: registrationId,
      preKeyId: preKeyId,
      signedPreKeyId: signedPreKeyId,
      kyberPreKeyId: kyberPreKeyId,
      kyberCiphertextTagged: kyberCiphertextTagged,
      baseKey: baseKey,
      identityKey: identityKey,
      message: message,
      serialized: serialized,
    );
  }

  factory Omemo2PreKeySignalMessage.fromSerialized(Uint8List serialized) {
    if (serialized.isEmpty) {
      throw const Omemo2InvalidMessageException('empty PreKeySignalMessage');
    }
    final messageVersion = (serialized[0] >> 4) & 0xf;
    if (messageVersion < omemo2PreKyberCiphertextVersion) {
      throw Omemo2InvalidMessageException(
        'legacy PreKeySignalMessage version $messageVersion',
      );
    }
    if (messageVersion > omemo2CiphertextMessageVersion) {
      throw Omemo2InvalidMessageException(
        'unknown PreKeySignalMessage version $messageVersion',
      );
    }
    if (messageVersion == omemo2PreKyberCiphertextVersion) {
      throw const Omemo2InvalidMessageException('X3DH no longer supported');
    }

    final reader = _ProtoReader(serialized.sublist(1));
    int? preKeyId;
    Uint8List? baseKeyBytes;
    Uint8List? identityKeyBytes;
    Uint8List? nested;
    var registrationId = 0;
    int? signedPreKeyId;
    int? kyberPreKeyId;
    Uint8List? kyberCt;

    while (!reader.isDone) {
      final tag = reader.readTag();
      final fn = reader.fieldNumber(tag);
      final wt = reader.wireType(tag);
      switch (fn) {
        case 1:
          preKeyId = reader.readUint32();
        case 2:
          baseKeyBytes = reader.readBytes();
        case 3:
          identityKeyBytes = reader.readBytes();
        case 4:
          nested = reader.readBytes();
        case 5:
          registrationId = reader.readUint32();
        case 6:
          signedPreKeyId = reader.readUint32();
        case 7:
          kyberPreKeyId = reader.readUint32();
        case 8:
          kyberCt = reader.readBytes();
        default:
          reader.skip(wt);
      }
    }

    if (baseKeyBytes == null ||
        identityKeyBytes == null ||
        nested == null ||
        signedPreKeyId == null) {
      throw const Omemo2InvalidMessageException(
        'incomplete PreKeySignalMessage',
      );
    }
    if (kyberPreKeyId == null || kyberCt == null) {
      throw const Omemo2InvalidMessageException(
        'Kyber pre key must be present for this session version',
      );
    }

    return Omemo2PreKeySignalMessage(
      messageVersion: messageVersion,
      registrationId: registrationId,
      preKeyId: preKeyId,
      signedPreKeyId: signedPreKeyId,
      kyberPreKeyId: kyberPreKeyId,
      kyberCiphertextTagged: kyberCt,
      baseKey: Curve.decodePoint(baseKeyBytes, 0),
      identityKey: IdentityKey(Curve.decodePoint(identityKeyBytes, 0)),
      message: Omemo2SignalMessage.fromSerialized(nested),
      serialized: serialized,
    );
  }

  final int messageVersion;
  final int registrationId;
  final int? preKeyId;
  final int signedPreKeyId;
  final int kyberPreKeyId;
  final Uint8List kyberCiphertextTagged;
  final ECPublicKey baseKey;
  final IdentityKey identityKey;
  final Omemo2SignalMessage message;
  final Uint8List serialized;

  bool get isPreKey => true;
}

/// Discriminated ciphertext wrapped for `<key>` content.
sealed class Omemo2CiphertextMessage {
  Uint8List serialize();
  bool get isPreKey;
}

final class Omemo2PreKeyCiphertext extends Omemo2CiphertextMessage {
  Omemo2PreKeyCiphertext(this.message);
  final Omemo2PreKeySignalMessage message;
  @override
  Uint8List serialize() => message.serialized;
  @override
  bool get isPreKey => true;
}

final class Omemo2WhisperCiphertext extends Omemo2CiphertextMessage {
  Omemo2WhisperCiphertext(this.message);
  final Omemo2SignalMessage message;
  @override
  Uint8List serialize() => message.serialized;
  @override
  bool get isPreKey => false;
}

/// Parse opaque `<key>` bytes into a PreKey or Whisper message.
Omemo2CiphertextMessage parseOmemo2Ciphertext(Uint8List bytes) {
  if (bytes.isEmpty) {
    throw const Omemo2InvalidMessageException('empty ciphertext');
  }
  // PreKey type is indicated by OMEMO `kex` attribute, but we also probe:
  // version-4 PreKey always has kyber fields; Whisper has trailing MAC and
  // no outer kyber id. Prefer explicit [isPreKey] from the caller when known.
  try {
    return Omemo2PreKeyCiphertext(
      Omemo2PreKeySignalMessage.fromSerialized(bytes),
    );
  } on Omemo2InvalidMessageException {
    return Omemo2WhisperCiphertext(Omemo2SignalMessage.fromSerialized(bytes));
  }
}
