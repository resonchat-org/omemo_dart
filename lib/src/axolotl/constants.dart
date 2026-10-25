// OMEMO 0.3.0 / Conversations axolotl constants.

/// AES-128-GCM payload key length.
const int axolotlAesKeyLength = 16;

/// GCM IV length used by Conversations / Smack / atalk VAxolotl.
const int axolotlIvLength = 12;

/// GCM authentication tag length (bits → bytes).
const int axolotlGcmTagLength = 16;

/// When true (Conversations default), the GCM tag is stripped from `<payload>`
/// and concatenated onto the inner AES key before Signal-encrypting each
/// per-device `<key>`: `key(16) ‖ tag(16)` = 32 bytes.
const bool axolotlPutAuthTagIntoKey = true;

/// Default number of one-time prekeys to publish (Conversations uses 100).
const int axolotlDefaultPreKeyCount = 100;

/// Hard cap on one-time prekeys in one published PEP bundle.
///
/// Older builds replenished by *adding* a full batch on every connect, so a
/// long-lived account can hold thousands of unused prekeys. Publishing all of
/// them exceeds servers' max stanza size (seen as `XML stanza is too big` and
/// a reconnect loop). Keep the wire bundle bounded even before the local store
/// is cleaned up.
const int axolotlMaxPublishedPreKeyCount = axolotlDefaultPreKeyCount;
