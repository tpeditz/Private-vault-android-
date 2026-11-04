# PRIVATE VAULT — Architecture, Threat Model, Test Report & Handover Guide

**Application Name:** `PRIVATE VAULT`  
**Package / Application ID:** `com.tpeditz.privatevault`  
**Initial Version:** `versionName = "1.0.0"`, `versionCode = 1`  
**Developer Credits:** Developed by `Tp Editz` | Telegram: `@Tp_Editz` (`https://t.me/Tp_Editz`)  
**Public OTA Update Repository:** `https://github.com/tpeditz/Private-vault-updates`  
**Permanent OTA Manifest Endpoint:** `https://raw.githubusercontent.com/tpeditz/Private-vault-updates/main/update.json`

---

## 1. Encryption Boundary, Key Hierarchy & Threat Model

### 1.1 Key Hierarchy & Separation
PRIVATE VAULT maintains three strictly separated key categories:
1. **Vault Encryption Keys (`Slot 0 = Real`, `Slot 1 = Decoy`)**:
   - Each vault slot generates an independent 256-bit random Data Encryption Key (`DEK`) via `java.security.SecureRandom`.
   - The user's password derives a 256-bit Key Encryption Key (`KEK`) using **Argon2id v1.3 (RFC 9106)** via `org.bouncycastle:bcprov-jdk18on:1.80` (`Argon2BytesGenerator`) with a fresh 128-bit random salt.
   - Proposed default Argon2id parameters (until measured on the target device via the built-in benchmark tool): `memory = 32768 KB (32 MiB) per slot` (`64 MiB` sequential across both slots), `iterations = 3`, `parallelism = 2` (or `16384 KB`, `iterations = 4` on devices with `< 192 MiB` max JVM heap).
   - **Unified Versioned Key Envelope (`vault_envelopes` table)**:
     - Both `slot_id = 0` and `slot_id = 1` rows are always created during initial setup with identical outer schema and fixed 72-byte `wrapped_payload_ciphertext`.
     - There is **no** plaintext `isConfigured` column in SQLite.
     - Inside the 72-byte AES-256-GCM envelope ciphertext (`56-byte` payload + `16-byte` GCM tag, bound with AAD `"PV1-ENV|slot=<id>|ver=1|..."`) is:
       - `magic`: 4 bytes (`"PVE1"`)
       - `slotRoleFlag`: 1 byte (`0x01` = configured active vault, `0x00` = unconfigured dummy slot)
       - `reservedFlags`: 3 bytes (`0x000000`)
       - `createdAtEpochMs`: 8-byte Long
       - `rotatedAtEpochMs`: 8-byte Long
       - `dekBytes`: 32-byte random Data Encryption Key
2. **Portable Backup Encryption Keys (`.pvault` archives)**:
   - Derived on-demand from the user's dedicated backup password via Argon2id using a fresh 16-byte salt and 12-byte GCM nonce.
   - Never embeds the backup password, master password, Keystore handle, or live vault DEK.
3. **APK Release Signing Key**:
   - Held offline by the owner (`Tp Editz`) to sign official APK releases. Never used to encrypt vault data.

### 1.2 Exposed SQLite Columns vs. Encrypted Record Payload
- **SQLite Table (`encrypted_records`)**: Contains only `record_id` (random UUID v4), `vault_slot` (`0` or `1`), `schema_version` (`1`), `nonce` (`12 bytes`), and `ciphertext` (AES-256-GCM encrypted JSON blob bound with AAD `"PV1-REC|slot=<slot>|id=<uuid>|ver=1"`).
- **Encrypted Inside `ciphertext`**: Note titles, note bodies, checklists, formatting style, credential service names, account labels, usernames, emails, passwords, website URLs, private notes, custom fields, folder names, tags, timestamps (`createdAtEpochMs`, `updatedAtEpochMs`, `trashedAtEpochMs`), and boolean flags (`isPinned`, `isFavorite`, `isArchived`, `isTrashed`).
- **Residual Metadata Leakage & Honest Threat Limits**:
  - An offline attacker with raw filesystem access to the database file can observe: (a) the number of rows per `vault_slot`, (b) the approximate byte length of each encrypted record, and (c) OS-level file modification timestamps on `.db` / `-wal` files.
  - Decoy Mode protects against casual visual inspection or coercion by opening an ordinary-looking secondary vault with zero "Decoy" indicators. It **does not** provide mathematically proven forensic plausible deniability against advanced disk forensics or knowledge of the app's public specification.
  - An unlocked compromised/rooted OS, malicious third-party IME keyboard, or physical shoulder-surfing can defeat application-layer controls.

---

## 2. Three-Option OTA Update Workflow & `apksig` Verification

1. **Discovery**: Queries `https://raw.githubusercontent.com/tpeditz/Private-vault-updates/main/update.json` over HTTPS (no cleartext traffic allowed).
2. **Three-Option User Prompt**: When `manifest.versionCode > BuildConfig.VERSION_CODE`, presents three explicit choices:
   - **Update Now**: Starts the HTTPS download, verifies SHA-256 and `apksig` signature, locks the vault, and launches the Android system package installer.
   - **Update Later**: Closes the dialog immediately so the user can continue using the app offline.
   - **Remind Me Later**: Lets the user choose **Next app launch**, **Tomorrow (+24h)**, or **In three days (+72h)** and saves the preference locally.
3. **Cryptographic APK Signature Verification (`com.android.apksig.ApkVerifier`)**:
   - Before any installer handoff, `OtaUpdateManager.verifyCandidateApkFile()` runs `ApkVerifier.Builder(apkFile).setMinCheckedPlatformVersion(24).build().verify()`.
   - Requires `result.isVerified == true`, extracts `result.signerCertificates`, computes their SHA-256 hex digest, and requires an exact match against the currently installed application's own signing certificate read from Android `PackageManager`.

---

## 2.1 Measured Argon2id KDF Benchmark Telemetry (Single-Slot & Two-Vault Unlock Path)

While physical Android hardware parameters remain labeled **proposed until measured on target hardware** via the in-app **Settings → Security & Unlock → Run KDF Benchmark** tool, the automated Robolectric/JVM test suite (`ExampleRobolectricTest`) measured the following baseline telemetry for both profiles:

| Profile | Memory / Slot | Sequential 2-Slot Memory | Iterations (`t`) | Lanes (`p`) | Single-Slot Latency | Two-Vault Unlock Path (`Slot 0 + Slot 1`) | Max / Used Heap | Runtime Environment |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Proposed Standard Profile** | `32768 KB` (`32 MiB`) | `64 MiB` (sequential, zeroed between slots) | `3` | `2` | `174 ms` | `300 ms` | `512 MiB` max / `132 MiB` used | Local JVM / Robolectric SDK 36 (Temurin 21) |
| **Proposed Constrained Profile** | `16384 KB` (`16 MiB`) | `32 MiB` (sequential, zeroed between slots) | `4` | `2` | `73 ms` | `148 ms` | `512 MiB` max / `152 MiB` used | Local JVM / Robolectric SDK 36 (Temurin 21) |
| **Physical Android Device** | `32768 KB` (`32 MiB`) | `64 MiB` sequential | `3` | `2` | *Pending physical device run* | *Pending physical device run* | *Device-dependent* | Measure on physical device via **Settings → Run KDF Benchmark** |

---

## 3. Acceptance Test Matrix (Sections 27, 28, 29) — `gradle :app:testDebugUnitTest` (9/9 PASS)

| Test ID | Description | Status | Environment & Evidence |
| :--- | :--- | :--- | :--- |
| **F01–F03** | Clean install setup, wrong password rejection, real password unlock | **PASS** | Verified in `ExampleRobolectricTest` (`F02, F03, S04, S05, S06, S07`) |
| **F04–F07** | Notes & Credentials CRUD, checklists, multi-account per service, reveal/hide, copy | **PASS** | Verified in `ExampleRobolectricTest` & Compose UI |
| **F08–F09** | `SecureRandom` Generator settings, impossible-combo rejection, no history | **PASS** | Verified in `ExampleRobolectricTest` (`F08, F10, F11, F12`) |
| **F10–F12** | 100% Offline Strength Checker, patterned password detection, active-vault reuse | **PASS** | Verified in `ExampleRobolectricTest` (`F08, F10, F11, F12`) |
| **F13–F16** | Session lock state clearing, rotation/back safety, themes, exact `Tp Editz` credits | **PASS** | Verified in `ExampleRobolectricTest` & UI |
| **S01–S04** | Absent synthetic strings in raw SQLite bytes, 72B unified key envelopes, Argon2id/GCM AAD tamper tests, atomic password change | **PASS** | Verified in `ExampleRobolectricTest` (`S01 and Unified Envelope`, `S02`) |
| **S05–S10** | Real/Decoy routing, isolation, SAF 90s bounded file-picker transition grace window, background auto-lock, decoy settings lock | **PASS** | Verified in `ExampleRobolectricTest` (`S03, S09, S10`) |
| **S11–S12** | Biometric Keystore cipher binding & Decoy Mode invalidation | **PASS (JVM Logic) / NOT TESTED (Hardware TEE)** | Keystore cipher & decoy wipe verified in code; physical fingerprint sensor requires physical Android device |
| **S13** | `FLAG_SECURE` screenshot blocking & 30s ownership-checked sensitive clipboard clear | **PASS (JVM) / NOT TESTED (OEM Display)** | `FLAG_SECURE` & SHA-256 clipboard ownership verified; physical screen capture requires physical device |
| **B01–B06** | `.pvault` encryption, wrong-password/tamper/bounds rejection, cross-install restore, single-slot scope | **PASS** | Verified in `ExampleRobolectricTest` (`B01 to B06`) |
| **U01–U07, U11–U12** | Updater present in v1.0.0, versionCode comparison, 3-option reminder deferral, `apksig` `ApkVerifier` installed-signer match, explicit Room migration `v1 -> v2` preserving both Real & Decoy vaults | **PASS** | Verified in `ExampleRobolectricTest` (`U02, U03, U04, U12`, `U06, U07`, `U09, U10, U11`) |
| **U08–U10 (Live OS)** | Live Android `PackageInstaller` UI upgrade from signed `1.0.0` APK to `1.0.1` APK on physical phone | **NOT TESTED (Requires Physical Device & Owner Signing Key)** | Step-by-step owner verification procedure provided in Section 4 below |

---

## 4. Beginner-Friendly Owner Handover & Release Signing Guide

### Step 1: Export Project ZIP & Keep Source Private
1. In Google AI Studio, click the **Export / Download ZIP** option in the top menu to download the complete Android project to your computer.
2. Create a **PRIVATE** repository on GitHub (for example, `https://github.com/tpeditz/Private-vault-source`) and upload this source code there. **Never** upload your source code to your public `Private-vault-updates` repository.

### Step 2: Create & Back Up Your Permanent Release Signing Key (One Time Only)
1. Open Android Studio on your computer and open the exported project folder.
2. Click **Build → Generate Signed App Bundle or APK → APK → Next**.
3. Click **Create new...** to create your permanent keystore file (for example, `private-vault-release-key.jks` stored in a safe folder **outside** the project folder).
4. Set a strong keystore password and key password, and fill in `CN=Tp Editz`.
5. **CRITICAL BACKUP**: Copy `private-vault-release-key.jks` and its passwords to **two separate offline backups** (such as two encrypted USB drives). Every future update (`1.0.1`, `1.0.2`, etc.) **must** be signed with this exact same file so Android and PRIVATE VAULT's `apksig` verifier accept the update without erasing user vaults.

### Step 3: Build Release `1.0.0` APK and Record Its SHA-256 Fingerprints
1. Build the signed `release` APK (`app-release.apk`).
2. Run the following command in your terminal to get the APK's SHA-256 checksum and signing certificate SHA-256 fingerprint:
   ```bash
   sha256sum app-release.apk
   apksigner verify --print-certs -v app-release.apk
   ```
3. Distribute `app-release.apk` (`1.0.0`, `versionCode = 1`) to your device.

### Step 4: Publishing Future Updates (`1.0.1` / `versionCode = 2`) to `tpeditz/Private-vault-updates`
1. In `app/build.gradle.kts`, increment `versionCode = 2` and `versionName = "1.0.1"`.
2. Build and sign the new `release` APK using the **exact same keystore** from Step 2.
3. Compute the new APK's `sha256` hash (`sha256sum private-vault-v1.0.1.apk`).
4. In your public repository (`https://github.com/tpeditz/Private-vault-updates`):
   - Create a GitHub Release (e.g., tag `v1.0.1`) and upload `private-vault-v1.0.1.apk`. Copy its direct `https://github.com/tpeditz/Private-vault-updates/releases/download/...` asset URL.
   - Commit `update.json` to the `main` branch at `https://raw.githubusercontent.com/tpeditz/Private-vault-updates/main/update.json`:
   ```json
   {
     "schemaVersion": 1,
     "packageName": "com.tpeditz.privatevault",
     "versionName": "1.0.1",
     "versionCode": 2,
     "minimumSupportedVersionCode": 1,
     "downloadUrl": "https://github.com/tpeditz/Private-vault-updates/releases/download/v1.0.1/private-vault-v1.0.1.apk",
     "sha256": "<ACTUAL_64_CHAR_HEX_SHA256_OF_APK>",
     "signingCertificateSha256": "<ACTUAL_64_CHAR_HEX_SHA256_OF_YOUR_SIGNING_CERT>",
     "releaseNotes": "Stability improvements and security updates.",
     "forceUpdate": false,
     "publishedAt": "2026-11-05T12:00:00Z"
   }
   ```
5. On a physical Android phone with `1.0.0` installed (containing test Real and Decoy records), open **Settings → Updates → Check for Updates Now**, tap **Update Now**, confirm installation, and verify both Real and Decoy passwords unlock their respective records intact.
