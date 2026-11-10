# PRIVATE VAULT — Architecture, Security Audit & Release Handover (`v1.0.4`)

## 1. Identity & Developer Credits
- **Application Name:** `PRIVATE VAULT`
- **Android Application ID:** `com.tpeditz.privatevault`
- **Version:** `1.0.4` (`versionCode = 5`, `minSdk = 24`, `targetSdk = 36`)
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
   - **Unicode Normalization (`PV-SEC-011`):** Password `CharArray` inputs are canonicalized to Unicode NFC before UTF-8 byte encoding (with automatic fallback to legacy non-NFC bytes when unlocking or restoring pre-v1.0.4 vaults/backups containing decomposed characters).
   - **Single-Flight Serialization (`R03`):** All Argon2id operations are serialized through a `Mutex` in `VaultRepository` so concurrent unlock or password-rotation calls cannot race or exhaust heap memory.
2. **Unified 72-Byte Key Envelopes (`vault_envelopes` — `PV-CRYPTO-001`, `PV-SEC-006`):**
   - Both `slot_id = 0` (Primary/Real Vault) and `slot_id = 1` (Decoy Vault) rows always exist on disk with identical 72-byte `wrapped_payload_ciphertext` blobs (`56B inner payload + 16B GCM tag`).
   - Inner payload layout: `4B Magic "PVE1" | 1B slotRoleFlag | 1B decoyPolicyFlag | 2B reserved (0x0000) | 8B createdAtEpochMs | 8B rotatedAtEpochMs | 32B DEK`.
   - Strict header validation enforces valid `slotRoleFlag`, valid `decoyPolicyFlag`, zeroed reserved bytes, and non-negative timestamps before accepting an unwrapped envelope.
   - When Decoy Mode is disabled (`PV-SEC-006`), Slot 1's dummy envelope is sealed with an unrecoverable 32-byte random CSPRNG KEK (never derived from any static password) and virtual default folders are synthesized in memory so an empty vault writes zero rows to `encrypted_records` (`PV-SEC-009`).
   - **Authoritative Decoy Policy Flag (`R01`):** Slot 0's inner envelope stores `decoyPolicyFlag` (`0x01` when Decoy Mode is active, `0x00` when disabled) inside the AES-256-GCM authenticated payload.
3. **Encrypted Records & Composite Primary Key (`encrypted_records` — `N01`, `PV-SEC-010`, `PV-PRIV-001`):**
   - Schema Version 3 enforces `PRIMARY KEY(vault_slot, record_id)` with non-destructive `MIGRATION_1_2` and `MIGRATION_2_3`.
   - Every Note, Credential, and custom VaultFolder is encrypted as a single JSON payload under AES-256-GCM bound to `AAD = "PV1-REC|slot=$vaultSlot|id=$recordId|ver=$schemaVersion"`.
   - **Full Cryptographic DEK Rotation (`PV-SEC-010`):** When rotating a vault password with `rekeyAllRecordsWithNewDek = true`, a fresh 256-bit DEK is generated and all records in that slot are re-encrypted atomically inside a single Room `@Transaction`.
   - **Local Threat Model & Metadata Boundary (`PV-PRIV-001`):** While all record titles, usernames, passwords, bodies, tags, and custom fields are encrypted with AES-256-GCM, raw SQLite inspection on a rooted device can observe row counts per `vault_slot`, ciphertext byte lengths, and random UUID `record_id` values. Plausible deniability protects against interactive unlock coercion and UI inspection (`PV-SEC-008`), not forensic comparison of unpadded SQLite table row counts.

---

## 3. Portable `.pvault` Backup & Restore (`U01`, `U02`, `PV-DATA-001`, `PV-BUG-009`)
- Top-level `ActivityResultContracts.CreateDocument` and `ActivityResultContracts.OpenDocument` launchers are registered at the root `MainActivity` composable boundary.
- **Selective Export Scope (`PV-BUG-009`):** Users can export **All Data**, **Notes Only**, or **Passwords Only** into an Argon2id + AES-256-GCM `.pvault` container.
- **Strict Fail-Closed Restore Validation (`PV-DATA-001`):** `PortableBackupEngine.decryptAndValidateBackup` strictly requires a present, non-null `JSONArray` under `"records"`, validates every entry's `recordType` and non-blank `id` before any database mutation, repairs orphaned `folderId` references, and requires explicit confirmation before replacing a non-empty vault with a 0-record backup.

---

## 4. OTA Update Verification & Unified Release Signing (`N04`, `PV-REL-001`, `PV-SEC-012`)
- **Strict Repository Allowlist (`R04`):** Production builds require HTTPS URLs under `raw.githubusercontent.com/tpeditz/Private-vault-updates/...` and `github.com/tpeditz/Private-vault-updates/releases/download/...`.
- **Fail-Closed Verification (`N04`):** `OtaUpdateManager.verifyCandidateApkFile` verifies SHA-256 file digest, `com.android.apksig.ApkVerifier` signature, exact SHA-256 signer certificate match against the installed app, and non-null archive metadata with `versionCode > installedVersionCode`.
- **Release Signing Contract (`PV-REL-001`, `PV-DOC-001`):**
  - `app/build.gradle.kts` resolves release signing credentials from environment variables (`KEYSTORE_PATH` / `PV_RELEASE_STORE_FILE`, `STORE_PASSWORD` / `PV_RELEASE_STORE_PASSWORD`, `KEY_ALIAS` / `PV_RELEASE_KEY_ALIAS`, `KEY_PASSWORD` / `PV_RELEASE_KEY_PASSWORD`).
  - No keystore or `.base64` private key material is tracked in Git. GitHub Actions (`publish-ota.yml` and `build-apk.yml`) require GitHub Repository Secrets (`RELEASE_KEYSTORE_BASE64`, `RELEASE_KEYSTORE_PASSWORD`, `RELEASE_KEY_ALIAS`, `RELEASE_KEY_PASSWORD`) and verify the signed APK with `apksigner verify --print-certs` before publishing.
