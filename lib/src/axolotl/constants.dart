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
