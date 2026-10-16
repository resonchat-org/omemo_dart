// OMEMO2 / monocles PQXDH constants matching libsignal ≥0.94.1.
//
// Proto-XEP §5.3: concrete PQXDH parameters are libsignal's, not chosen by
// the XEP. Interop requires reproducing these values exactly.

/// Wire ciphertext message version (PQXDH / Kyber-capable).
const int omemo2CiphertextMessageVersion = 4;

/// Classical Signal version (X3DH-only) — rejected for OMEMO2 sessions.
const int omemo2PreKyberCiphertextVersion = 3;

/// HKDF-Expand info for PQXDH handshake key derivation (libsignal `pqxdh.rs`).
///
/// Note the literal still says `CRYSTALS-KYBER-1024` even when the KEM on the
/// wire is ML-KEM-1024 (`0x0A`); libsignal did not rename the label.
const String omemo2PqxdhHkdfLabel =
    'WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024';

/// Double Ratchet root/chain HKDF info (unchanged from classical Signal).
const String omemo2WhisperRatchetLabel = 'WhisperRatchet';

/// Message-keys HKDF info (unchanged from classical Signal).
const String omemo2WhisperMessageKeysLabel = 'WhisperMessageKeys';

/// libsignal ML-KEM-1024 type tag (`kem.rs` / CryptoHelper).
const int omemo2MlKem1024Tag = 0x0A;

/// Round-3 Kyber-1024 tag — must be refused for OMEMO2.
const int omemo2Kyber1024Round3Tag = 0x08;

/// ML-KEM-1024 sizes (FIPS 203).
const int omemo2MlKemPublicKeyLength = 1568;
const int omemo2MlKemSecretKeyLength = 3168;
const int omemo2MlKemCiphertextLength = 1568;
const int omemo2MlKemSharedSecretLength = 32;

/// Signal message MAC truncation (bytes).
const int omemo2MacLength = 8;
