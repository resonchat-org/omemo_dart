import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart' as ls;
import 'package:logging/logging.dart';
import 'package:synchronized/synchronized.dart';

import 'package:omemo_dart/src/common/can_send.dart';
import 'package:omemo_dart/src/common/errors.dart';
import 'package:omemo_dart/src/common/helpers.dart' as helpers;
import 'package:omemo_dart/src/omemo2/address.dart';
import 'package:omemo_dart/src/omemo2/bootstrap.dart';
import 'package:omemo_dart/src/omemo2/bundle.dart';
import 'package:omemo_dart/src/omemo2/decryption_result.dart';
import 'package:omemo_dart/src/omemo2/device.dart';
import 'package:omemo_dart/src/omemo2/encrypted_key.dart';
import 'package:omemo_dart/src/omemo2/encryption_result.dart';
import 'package:omemo_dart/src/omemo2/establish.dart';
import 'package:omemo_dart/src/omemo2/payload.dart';
import 'package:omemo_dart/src/omemo2/stanza.dart';

/// Fetch remote OMEMO2 device ids for [jid].
typedef Omemo2FetchDeviceList = Future<List<int>?> Function(String jid);

/// Fetch a remote OMEMO2 PEP bundle.
typedef Omemo2FetchBundle =
    Future<Omemo2PreKeyBundle?> Function(String jid, int deviceId);

/// Persist the local device snapshot.
typedef Omemo2CommitDevice = Future<void> Function(Omemo2Device device);

Future<void> omemo2CommitDeviceStub(Omemo2Device _) async {}

/// monocles OMEMO2 manager (native libsignal PQXDH + SessionCipher + SPQR).
///
/// XMPP-agnostic: same interaction shape as `AxolotlOmemoManager` —
/// `onOutgoingStanza` / `onIncomingStanza` plus fetch callbacks. Callers build
/// `urn:monocles:omemo-pq:1` XML themselves.
class Omemo2Manager {
  Omemo2Manager(
    this._device, {
    required this.fetchDeviceList,
    required this.fetchBundle,
    this.commitDevice = omemo2CommitDeviceStub,
  });

  final Logger _log = Logger('Omemo2Manager');
  final Lock _lock = Lock();

  Omemo2Device _device;
  final Omemo2FetchDeviceList fetchDeviceList;
  final Omemo2FetchBundle fetchBundle;
  final Omemo2CommitDevice commitDevice;

  final Map<String, List<int>> _deviceList = {};

  Future<Omemo2Device> getDevice() async => _device;

  Future<int> getDeviceId() async => _device.id;

  Future<void> setDevice(Omemo2Device device) async {
    await _lock.synchronized(() async {
      _device = device;
      await _device.ensureStores();
    });
  }

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

  Future<Omemo2EncryptionResult> onOutgoingStanza(
    Omemo2OutgoingStanza stanza,
  ) async {
    return _lock.synchronized(() async {
      await omemo2EnsureLibSignal();
      await _device.ensureStores();

      final ourId = _device.id;
      final ourJid = _device.jid;
      final cipher = _device.sessionCipher();

      // Strict allow-list validation happens before the payload is sealed,
      // before any session is created or ratcheted, and before commitDevice.
      // A missing entry is a caller bug: fail the whole send instead of
      // silently falling back to the announced device list.
      final overrides = stanza.recipientDeviceIds;
      if (overrides != null) {
        final missing = <String>[
          for (final jid in stanza.recipientJids)
            if (!overrides.containsKey(jid)) jid,
        ];
        if (missing.isNotEmpty) {
          return Omemo2EncryptionResult(
            ciphertext: null,
            commit: null,
            encryptedKeys: const {},
            deviceEncryptionErrors: {
              for (final jid in missing)
                jid: [
                  EncryptToJidError(
                    null,
                    const MissingRecipientDeviceOverrideError(),
                  ),
                ],
            },
            newSessions: const {},
            canSend: false,
          );
        }
      }

      late final Uint8List messageKey;
      List<int>? ciphertext;
      List<int>? commit;

      if (stanza.payload != null) {
        messageKey = Uint8List.fromList(helpers.generateRandomBytes(32));
        final primary = stanza.recipientJids.first;
        final binding = omemo2ContextBinding(
          senderBareJid: ourJid,
          recipientBareJid: primary,
          sourceDeviceId: ourId,
        );
        final sealed = await omemo2SealPayload(
          messageKey: messageKey,
          plaintext: stanza.payload!,
          binding: binding,
        );
        ciphertext = sealed.ciphertextWithMac;
        commit = sealed.commit;
      } else {
        messageKey = Uint8List.fromList(helpers.generateRandomBytes(32));
        ciphertext = null;
        commit = null;
      }

      final encryptedKeys = <String, List<Omemo2EncryptedKey>>{};
      final errors = <String, List<EncryptToJidError>>{};
      final newSessions = <String, List<int>>{};
      final successes = <String, int>{};

      for (final jid in stanza.recipientJids) {
        // [overrides] is validated above, so the lookup cannot fail here.
        final devices = overrides == null
            ? await getDevicesFor(jid)
            : overrides[jid]!;
        final targetIds = List<int>.from(devices);
        if (jid == ourJid) {
          targetIds.removeWhere((id) => id == ourId);
        }

        if (targetIds.isEmpty) {
          if (jid == ourJid) {
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
            final addr = omemo2ProtocolAddress(jid, deviceId);
            if (!await _device.sessionStore.containsSession(addr)) {
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
              await _processBundle(bundle);
              newSessions.putIfAbsent(jid, () => []).add(deviceId);
            }

            final encrypted = await cipher.encrypt(addr, messageKey);
            encryptedKeys
                .putIfAbsent(jid, () => [])
                .add(
                  Omemo2EncryptedKey(
                    deviceId,
                    base64Encode(encrypted.ciphertext),
                    encrypted.isPreKeyMessage,
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

      // Same flush as the classic manager: every session this fan-out
      // created or ratcheted is durable before the stanza goes out.
      await commitDevice(_device);

      return Omemo2EncryptionResult(
        ciphertext: ciphertext,
        commit: commit,
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

  Future<Omemo2DecryptionResult> onIncomingStanza(
    Omemo2IncomingStanza stanza,
  ) async {
    return _lock.synchronized(() async {
      await omemo2EnsureLibSignal();
      await _device.ensureStores();

      final ourId = _device.id;
      final candidates = stanza.keys.where((k) => k.rid == ourId).toList();
      if (candidates.isEmpty) {
        return const Omemo2DecryptionResult(
          payload: null,
          newSessions: {},
          error: NotEncryptedForDeviceError(),
        );
      }

      final addr = omemo2ProtocolAddress(
        stanza.bareSenderJid,
        stanza.senderDeviceId,
      );
      final cipher = _device.sessionCipher();
      final newSessions = <String, List<int>>{};
      Object? lastError;

      for (final key in candidates) {
        try {
          final hadSession = await _device.sessionStore.containsSession(addr);
          final type = key.kex
              ? ls.CiphertextMessageType.preKey
              : ls.CiphertextMessageType.signal;
          final ct = ls.CiphertextMessage(
            type: type,
            ciphertext: Uint8List.fromList(key.data),
          );
          final messageKey = await cipher.decrypt(addr, ct);
          await commitDevice(_device);
          if (!hadSession) {
            newSessions
                .putIfAbsent(stanza.bareSenderJid, () => [])
                .add(stanza.senderDeviceId);
          }

          if (stanza.payload == null) {
            return Omemo2DecryptionResult(
              payload: null,
              newSessions: newSessions,
              error: null,
            );
          }
          final commit = stanza.commit;
          if (commit == null) {
            return Omemo2DecryptionResult(
              payload: null,
              newSessions: newSessions,
              error: const MalformedEncryptedKeyError(),
            );
          }
          final binding = omemo2ContextBinding(
            senderBareJid: stanza.bareSenderJid,
            recipientBareJid: stanza.recipientBareJid,
            sourceDeviceId: stanza.senderDeviceId,
          );
          final clear = await omemo2OpenPayload(
            messageKey: messageKey,
            ciphertextWithMac: stanza.payload!,
            commit: commit,
            binding: binding,
          );
          return Omemo2DecryptionResult(
            payload: utf8.decode(clear),
            newSessions: newSessions,
            error: null,
          );
        } catch (e, st) {
          _log.warning('decrypt from ${stanza.bareSenderJid} failed: $e\n$st');
          lastError = e;
        }
      }

      return Omemo2DecryptionResult(
        payload: null,
        newSessions: newSessions,
        error: MalformedCiphertextError(lastError ?? 'decrypt failed'),
      );
    });
  }

  Future<void> _processBundle(Omemo2PreKeyBundle bundle) =>
      omemo2EstablishSession(_device, bundle);
}
