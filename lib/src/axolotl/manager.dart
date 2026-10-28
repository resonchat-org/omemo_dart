import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal_protocol_dart/libsignal_protocol_dart.dart';
import 'package:logging/logging.dart';
import 'package:synchronized/synchronized.dart';

import 'package:omemo_dart/src/axolotl/bundle.dart';
import 'package:omemo_dart/src/axolotl/constants.dart';
import 'package:omemo_dart/src/axolotl/crypto.dart';
import 'package:omemo_dart/src/axolotl/decryption_result.dart';
import 'package:omemo_dart/src/axolotl/device.dart';
import 'package:omemo_dart/src/axolotl/encrypted_key.dart';
import 'package:omemo_dart/src/axolotl/encryption_result.dart';
import 'package:omemo_dart/src/axolotl/stanza.dart';
import 'package:omemo_dart/src/common/can_send.dart';
import 'package:omemo_dart/src/common/errors.dart';
import 'package:omemo_dart/src/common/helpers.dart' as helpers;

/// Fetch remote device ids for [jid].
typedef AxolotlFetchDeviceList = Future<List<int>?> Function(String jid);

/// Fetch a remote PEP bundle.
typedef AxolotlFetchBundle =
    Future<AxolotlBundle?> Function(String jid, int deviceId);

/// Persist the local device snapshot.
typedef AxolotlCommitDevice = Future<void> Function(AxolotlDevice device);

Future<void> axolotlCommitDeviceStub(AxolotlDevice _) async {}

/// OMEMO 0.3.0 / Conversations crypto manager (Signal + AES-128-GCM).
///
/// XMPP-agnostic: callers supply device-list / bundle fetch and build the
/// `eu.siacs.conversations.axolotl` XML themselves.
class AxolotlOmemoManager {
  AxolotlOmemoManager(
    this._device, {
    required this.fetchDeviceList,
    required this.fetchBundle,
    this.commitDevice = axolotlCommitDeviceStub,
  });

  final Logger _log = Logger('AxolotlOmemoManager');
  final Lock _lock = Lock();

  AxolotlDevice _device;
  final AxolotlFetchDeviceList fetchDeviceList;
  final AxolotlFetchBundle fetchBundle;
  final AxolotlCommitDevice commitDevice;

  final Map<String, List<int>> _deviceList = {};
  final Set<int> _trackedPreKeyIds = {};

  Future<AxolotlDevice> getDevice() async => _device;

  Future<int> getDeviceId() async => _device.deviceId;

  Future<void> setDevice(AxolotlDevice device) async {
    await _lock.synchronized(() async {
      _device = device;
      _trackedPreKeyIds
        ..clear()
        ..addAll(device.store.preKeyStore.store.keys);
    });
  }

  /// Remember remote device ids (e.g. from PEP push).
  Future<void> onDeviceListUpdate(String jid, List<int> ids) async {
    _deviceList[jid] = List<int>.from(ids);
  }

  Future<List<int>> getDevicesFor(String jid) async {
    final cached = _deviceList[jid];
    if (cached != null) return cached;
    final fetched = await fetchDeviceList(jid);
    if (fetched == null) return [];
    _deviceList[jid] = fetched;
    return fetched;
  }

  /// Build outbound axolotl ciphertext for [stanza].
  Future<AxolotlEncryptionResult> onOutgoingStanza(
    AxolotlOutgoingStanza stanza,
  ) async {
    return _lock.synchronized(() async {
      final ourId = await _device.deviceId;
      final ourJid = _device.jid;

      List<int>? ciphertext;
      List<int>? iv;
      late List<int> keyMaterial;

      if (stanza.payload != null) {
        final enc = await axolotlEncryptPayload(stanza.payload!);
        ciphertext = enc.ciphertextWithoutTag;
        iv = enc.iv;
        keyMaterial = enc.keyPlusTag;
      } else {
        // Key-transport: random 16-byte key, no auth tag (Conversations).
        keyMaterial = helpers.generateRandomBytes(16);
        ciphertext = null;
        iv = null;
      }

      final encryptedKeys = <String, List<AxolotlEncryptedKey>>{};
      final errors = <String, List<EncryptToJidError>>{};
      final newSessions = <String, List<int>>{};
      final successes = <String, int>{};

      for (final jid in stanza.recipientJids) {
        // Prefer a fresh fetchDeviceList over the PEP cache so application
        // trust filters (BTBV / per-fingerprint distrust) applied in the
        // fetch callback are not bypassed by an earlier unfiltered push.
        final fetched = await fetchDeviceList(jid);
        final devices = fetched ?? await getDevicesFor(jid);
        // Always include our own other devices when encrypting to ourselves
        // is requested by the caller (carbons path passes our bare JID).
        final targetIds = List<int>.from(devices);
        if (jid == ourJid) {
          targetIds.removeWhere((id) => id == ourId);
        }

        if (targetIds.isEmpty) {
          if (jid == ourJid) {
            // Single-device account: nothing to carbon-copy to.
            successes[jid] = (successes[jid] ?? 0) + 1;
            continue;
          }
          errors
              .putIfAbsent(jid, () => [])
              .add(
                EncryptToJidError(null, const NoKeyMaterialAvailableError()),
              );
          continue;
        }

        for (final deviceId in targetIds) {
          try {
            final address = SignalProtocolAddress(jid, deviceId);
            final hasSession = await _device.store.containsSession(address);
            if (!hasSession) {
              final bundle = await fetchBundle(jid, deviceId);
              if (bundle == null) {
                errors
                    .putIfAbsent(jid, () => [])
                    .add(
                      EncryptToJidError(
                        deviceId,
                        const NoKeyMaterialAvailableError(),
                      ),
                    );
                continue;
              }
              final builder = SessionBuilder.fromSignalStore(
                _device.store,
                address,
              );
              await builder.processPreKeyBundle(bundle.toPreKeyBundle());
              newSessions.putIfAbsent(jid, () => []).add(deviceId);
            }

            final cipher = SessionCipher.fromStore(_device.store, address);
            final message = await cipher.encrypt(
              Uint8List.fromList(keyMaterial),
            );
            encryptedKeys
                .putIfAbsent(jid, () => [])
                .add(
                  AxolotlEncryptedKey(
                    deviceId,
                    base64Encode(message.serialize()),
                    message.getType() == CiphertextMessage.prekeyType,
                  ),
                );
            successes[jid] = (successes[jid] ?? 0) + 1;
          } catch (e, st) {
            _log.warning('encrypt to $jid:$deviceId failed: $e\n$st');
            errors
                .putIfAbsent(jid, () => [])
                .add(EncryptToJidError(deviceId, MalformedCiphertextError(e)));
          }
        }
      }

      // Conversations `storeSession` runs inside encrypt, before the stanza
      // is sent. Flush every session this fan-out created or ratcheted.
      // Device-list expiry does not come through here: that only marks the
      // identity inactive and leaves the session row in place.
      await commitDevice(_device);

      return AxolotlEncryptionResult(
        ciphertext: ciphertext,
        iv: iv,
        encryptedKeys: encryptedKeys,
        deviceEncryptionErrors: errors,
        newSessions: newSessions,
        canSend: canSendAllDevicesReached(
          stanza.recipientJids,
          successes,
          errors,
        ),
      );
    });
  }

  /// Decrypt an inbound axolotl stanza addressed to our device.
  Future<AxolotlDecryptionResult> onIncomingStanza(
    AxolotlIncomingStanza stanza,
  ) async {
    return _lock.synchronized(() async {
      final ourId = await _device.deviceId;
      final candidates = stanza.keys.where((k) => k.rid == ourId).toList();
      if (candidates.isEmpty) {
        return const AxolotlDecryptionResult(
          payload: null,
          newSessions: {},
          error: NotEncryptedForDeviceError(),
        );
      }

      final address = SignalProtocolAddress(
        stanza.bareSenderJid,
        stanza.senderDeviceId,
      );
      final newSessions = <String, List<int>>{};
      Object? lastError;
      int? usedPreKeyId;

      for (final key in candidates) {
        try {
          final hadSession = await _device.store.containsSession(address);
          final cipher = SessionCipher.fromStore(_device.store, address);
          final raw = Uint8List.fromList(key.data);

          late Uint8List keyMaterial;
          if (key.prekey) {
            final preKeyMsg = PreKeySignalMessage(raw);
            keyMaterial = await cipher.decrypt(preKeyMsg);
            if (preKeyMsg.getPreKeyId().isPresent) {
              usedPreKeyId = preKeyMsg.getPreKeyId().value;
              await _device.store.removePreKey(usedPreKeyId);
              _trackedPreKeyIds.remove(usedPreKeyId);
            }
            if (!hadSession) {
              newSessions
                  .putIfAbsent(stanza.bareSenderJid, () => [])
                  .add(stanza.senderDeviceId);
            }
          } else {
            final signalMsg = SignalMessage.fromSerialized(raw);
            keyMaterial = await cipher.decryptFromSignal(signalMsg);
          }

          // SessionRecord (and a consumed one-time prekey) are durable before
          // the payload is opened. Conversations flushes the same way: the
          // libsignal store write happens inside decrypt, not after the body
          // is accepted. A device dropping off the PEP list does not delete
          // this record; only a key wipe does.
          await commitDevice(_device);

          String? payload;
          if (stanza.payload != null) {
            if (stanza.iv == null) {
              return AxolotlDecryptionResult(
                payload: null,
                newSessions: newSessions,
                usedPreKeyId: usedPreKeyId,
                error: MalformedCiphertextError('missing iv'),
              );
            }
            final plain = await axolotlDecryptPayload(
              ciphertextWithoutTag: stanza.payload!,
              keyPlusTag: keyMaterial,
              iv: stanza.iv!,
            );
            payload = utf8.decode(plain);
          }

          return AxolotlDecryptionResult(
            payload: payload,
            newSessions: newSessions,
            usedPreKeyId: usedPreKeyId,
            error: null,
          );
        } catch (e, st) {
          _log.fine('key candidate failed: $e\n$st');
          lastError = e;
        }
      }

      return AxolotlDecryptionResult(
        payload: null,
        newSessions: newSessions,
        usedPreKeyId: usedPreKeyId,
        error: MalformedCiphertextError(lastError ?? 'decrypt failed'),
      );
    });
  }

  /// Publishable bundle including tracked prekeys.
  ///
  /// The wire bundle is capped at [axolotlMaxPublishedPreKeyCount]. Accounts
  /// that accumulated thousands of prekeys under the old append-only
  /// replenish must not emit a stanza larger than the server accepts.
  Future<AxolotlBundle> getLocalBundle() {
    final available = [
      for (final id in _trackedPreKeyIds)
        if (_device.store.preKeyStore.store.containsKey(id)) id,
    ];
    final selected = available.length <= axolotlMaxPublishedPreKeyCount
        ? available
        : available.sublist(available.length - axolotlMaxPublishedPreKeyCount);
    return _device.toBundle(preKeyIds: selected);
  }

  /// Track newly created prekeys (call after [AxolotlDevice.generateNewDevice]
  /// or [AxolotlDevice.replenishPreKeys]).
  void trackPreKeyIds(Iterable<int> ids) {
    _trackedPreKeyIds.addAll(ids);
  }

  Future<List<int>> replenishPreKeys(int count) async {
    final ids = await _device.replenishPreKeys(count);
    trackPreKeyIds(ids);
    await commitDevice(_device);
    return ids;
  }
}
