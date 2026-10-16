# omemo_dart

`omemo_dart` helps Dart/Flutter XMPP clients implement OMEMO-family protocols.
It is XMPP-agnostic: callers map intermediary key/payload types to stanza XML.

## Stacks

| Stack | Entry | Protocol |
|-------|-------|----------|
| Shared | `package:omemo_dart/omemo_dart.dart` | `OmemoKeyPair`, helpers, shared errors / `canSend` |
| Axolotl | `package:omemo_dart/omemo_dart_axolotl.dart` | XEP-0384 **0.3.0** / Conversations (`eu.siacs.conversations.axolotl`) |
| OMEMO2 | `package:omemo_dart/omemo_dart_omemo2.dart` | monocles PQ-OMEMO2 (`urn:monocles:omemo-pq:1`) via native libsignal |

The classic XEP-0384 **0.8.3** stack has been removed from this fork.

### Manager boundary (Axolotl & OMEMO2)

Both protocol managers share the same interaction shape:

- construct with a local device + `fetchDeviceList` / `fetchBundle` callbacks
- `onOutgoingStanza` → encryption result (`encryptedKeys`, payload, `canSend`)
- `onIncomingStanza` → decryption result

OMEMO2 uses native `package:libsignal` (PQXDH + SessionCipher + SPQR). Prefer the
ResonChat path fork `packages/libsignal_dart` so Kyber generation uses NIST
ML-KEM-1024 (wire tag `0x0A`). **AGPL-3.0** applies when linking libsignal.

## Important Notes

- **This library has not been audited. Use at your own risk.**
- Axolotl targets Conversations wire compatibility.

## License

See the repository root. Native libsignal bindings are AGPL-3.0.
