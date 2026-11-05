# PRIVATE VAULT — Architecture, Security Audit & Release Handover (`v1.0.1`)

## 1. Identity & Developer Credits
- **Application Name:** `PRIVATE VAULT`
- **Android Application ID:** `com.tpeditz.privatevault`
- **Version:** `1.0.1` (`versionCode = 2`, `minSdk = 24`, `targetSdk = 36`)
- **Developer Credit:** `Developed by Tp Editz`
- **Telegram:** `@Tp_Editz` (`https://t.me/Tp_Editz`)
- **Instagram:** `@tp_ediitz` (`https://www.instagram.com/tp_ediitz/`)
- **Public OTA Release Repository:** `https://github.com/tpeditz/Private-vault-updates`
- **Permanent HTTPS Manifest Endpoint:** `https://raw.githubusercontent.com/tpeditz/Private-vault-updates/main/update.json`

---

## 2. Cryptographic & Storage Architecture
1. **Password Key Derivation (KDF):**
   - **Algorithm:** Argon2id v1.3 (RFC 9106) via `org.bouncycastle:bcprov-jdk18on:1.80`.
   - **Default Parameters:** `m = 32768 KB` (32 MiB per slot; `16384 KB` on constrained-heap devices), `t = 3`, `p = 2`, 16-byte CSPRNG salt, 32-byte (256-bit) output KEK.
   - **Single-Flight Serialization (`R03`):** All Argon2id operations are serialized through a `Mutex` in `VaultRepository` so concurrent unlock or password-rotation calls cannot race or exhaust heap memory.
2. **Unified 72-Byte Key Envelopes (`vault_envelopes`):**
   - Both `slot_id = 0` (Primary/Real Vault) and `slot_id = 1` (Decoy Vault) rows always exist on disk with identical 72-byte `wrapped_payload_ciphertext` blobs (`56B inner payload + 16B GCM tag`).
   - Inner payload layout: `4B Magic "PVE1" | 1B slotRoleFlag | 1B decoyPolicyFlag | 2B reserved | 8B createdAtEpochMs | 8B rotatedAtEpochMs | 32B DEK`.
   - **Authoritative Decoy Policy Flag (`R01`):** Slot 0's inner envelope stores `decoyPolicyFlag` (`0x01` when Decoy Mode is active, `0x00` when disabled) inside the AES-256-GCM authenticated payload. Even when the Decoy Vault has `0` records in `encrypted_records`, Decoy Mode remains recognized as active and continues to block biometric enrollment.
3. **Encrypted Records & Composite Primary Key (`encrypted_records` — `N01`):**
   - Schema Version 3 enforces `PRIMARY KEY(vault_slot, record_id)` with non-destructive `MIGRATION_1_2` and `MIGRATION_2_3`.
   - Every Note, Credential, and VaultFolder is encrypted as a single JSON payload under AES-256-GCM bound to `AAD = "PV1-REC|slot=$vaultSlot|id=$recordId|ver=$schemaVersion"`.
   - **Integrity Protection (`N02`):** Record decryption distinguishes valid records from corrupted/tampered ciphertexts (`RecordDecryptResult.Corrupted`). Ordinary backup export and `MERGE_KEEP_NEWEST` restore abort with `VaultRecordIntegrityException` if any existing record fails AEAD verification so corrupted ciphertext is never silently omitted or deleted.

---

## 3. Portable `.pvault` Backup & Restore (`U01`, `U02`, `R16`)
- Top-level `ActivityResultContracts.CreateDocument` and `ActivityResultContracts.OpenDocument` launchers are registered at the root `MainActivity` composable boundary so they survive screen transitions and SAF lifecycle events.
- **Export (`U01`):** Encrypts the active vault slot into a temporary file in `context.cacheDir/backup_staging/pending_export_<opId>.pvault`, opens a bounded 90-second SAF picker window, and copies the staged file to the user's chosen `Uri` on `Dispatchers.IO` inside `use {}`, deleting the temporary staging file in `finally`.
- **Restore (`U02`):** Stores the selected `Uri` in `VaultViewModel`, reads up to the 32 MiB safety ceiling on `Dispatchers.IO` inside `use {}`, verifies the `.pvault` Argon2id + AES-256-GCM tag in memory before touching SQLite, and commits to the bound `originSlotId`.

---

## 4. OTA Update Verification (`N04`, `R04`, `R14`, `R15`)
- **Strict Repository Allowlist (`R04`):** Production builds require HTTPS URLs under `raw.githubusercontent.com/tpeditz/Private-vault-updates/...` and `github.com/tpeditz/Private-vault-updates/releases/download/...`.
- **Fail-Closed Verification (`N04`):** `OtaUpdateManager.verifyCandidateApkFile` verifies:
  1. Exact SHA-256 file digest match against `update.json`.
  2. Cryptographic signature verification via `com.android.apksig.ApkVerifier`.
  3. Exact SHA-256 signer certificate match against the installed app's trusted signer(s).
  4. Non-null package archive metadata (`getPackageArchiveInfo` — fails closed if `null`) confirming matching `packageName` and `versionCode > installedVersionCode`.
