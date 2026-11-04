# PRIVATE VAULT — Final Revised Implementation Plan

A strictly offline-first, native Android privacy and security vault built with Kotlin, Jetpack Compose, and Material 3. It delivers four primary tools (**Private Notes**, **Password Vault**, **Cryptographic Password Generator**, and **Offline Password Strength Checker**), independently encrypted **Real and Decoy Vaults**, **AES-256-GCM encrypted manual backup and restore**, and a **self-verifying OTA APK Updater** backed by `https://github.com/tpeditz/Private-vault-updates`—with **zero** cloud, Firebase, or AI dependencies.

---

### User Review & Critical Decisions

> [!IMPORTANT]
> All five technical refinements and the three-option OTA update prompt workflow have been integrated into this plan. Click **Proceed** on this plan card to authorize code implementation.

- **Confirmed Decision 1 (Android `apksig` `ApkVerifier` — No `JarFile` Substitution)**:
  - Candidate APK signature verification uses the official Android **`com.android.tools.build:apksig` (`com.android.apksig.ApkVerifier`)** library directly on the downloaded APK file (`ApkVerifier.Builder(apkFile).setMinCheckedPlatformVersion(Build.VERSION.SDK_INT).build().verify()`).
  - Verification requires `result.isVerified == true` across V2/V3/V4 APK Signature Schemes (and V1 if applicable), extracts `result.signerCertificates`, computes the SHA-256 digest of the verified leaf signing certificate(s), and requires an exact byte-for-byte match against the currently installed application's own signing certificate digest read from `PackageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)`. `JarFile` certificate checks are never used.
- **Confirmed Decision 2 (Argon2id Proposed Parameters & Two-Vault Benchmark Recording)**:
  - Password key derivation uses **Argon2id** (RFC 9106 v1.3) via `org.bouncycastle:bcprov-jdk18on:1.80`.
  - Because every unlock attempt evaluates **both** `Slot 0` and `Slot 1` sequentially to avoid timing side-channels, the total unlock latency is `2 × single_slot_kdf_time`.
  - **Proposed Initial Parameters (Until Measured)**:
    - *Proposed Standard Profile*: `memory = 32768 KB (32 MiB) per slot` (`64 MiB` peak sequential work across 2 slots), `iterations = 3`, `parallelism = 2`.
    - *Proposed Constrained-Memory Profile* (when runtime max heap `< 192 MiB`): `memory = 16384 KB (16 MiB) per slot`, `iterations = 4`, `parallelism = 2`.
  - The app includes a built-in **KDF Benchmark & Telemetry Recorder** (displayed in Security Settings & Test Report) that records the actual device model, Android API level, single-slot KDF duration (`ms`), two-slot total unlock duration (`ms`), and heap usage (`MiB`) so parameters are empirically verified rather than assumed.
- **Confirmed Decision 3 (Single Unified Versioned Key-Envelope Format)**:
  - Resolved all conflicting slot descriptions into **one exact versioned `VaultEnvelopeEntity` format**.
  - There is **no** plaintext `isConfigured` column in SQLite. Both `slotId = 0` (Real) and `slotId = 1` (Decoy) rows always exist in the `vault_envelopes` table with identical outer column structure and fixed-size ciphertext lengths (`72 bytes`):
    - Outer SQLite columns: `slotId: Int` (`0` or `1`), `envelopeVersion: Int` (`1`), `kdfAlgorithm: String` (`"ARGON2ID_V13"`), `kdfMemoryKb: Int`, `kdfIterations: Int`, `kdfParallelism: Int`, `kdfSalt: ByteArray` (16 bytes), `wrapNonce: ByteArray` (12 bytes), `wrappedPayloadCiphertext: ByteArray` (72 bytes: 56-byte inner struct + 16-byte GCM tag), plus optional `biometricNonce: ByteArray?` and `biometricWrappedDek: ByteArray?` (null whenever Decoy is enabled or Biometrics disabled).
    - Encrypted Inner Envelope Payload (`56 bytes` before 16-byte GCM tag, bound with AAD `"PV1-ENV" || slotId || envelopeVersion || kdfMemoryKb || kdfIterations || kdfParallelism`):
      - `magic: ByteArray` (4 bytes: `"PVE1"`)
      - `slotRoleFlag: Byte` (`0x01` = active configured vault, `0x00` = unconfigured dummy slot)
      - `reservedFlags: ByteArray` (3 bytes, zeroed)
      - `createdAtEpochMs: Long` (8 bytes)
      - `rotatedAtEpochMs: Long` (8 bytes)
      - `dekBytes: ByteArray` (32 bytes: 256-bit random Data Encryption Key)
    - When Decoy Mode is not configured by the user, `Slot 1` is initialized with a random 256-bit throwaway key and `slotRoleFlag = 0x00`, making `Slot 0` and `Slot 1` indistinguishable at rest on disk.
- **Confirmed Decision 4 (Complete Removal of Unused Cloud/AI Dependencies)**:
  - Rather than leaving commented-out Firebase, Google Services, Retrofit, Moshi, CameraX, or AI dependencies in `app/build.gradle.kts`, `build.gradle.kts`, and `gradle/libs.versions.toml`, all unused cloud/AI plugins (`com.google.gms.google-services`, `secrets-gradle-plugin`) and library declarations are cleanly removed. Only required offline vault, Room, Compose, Navigation, Biometric, BouncyCastle, and `apksig` dependencies are present.
- **Confirmed Decision 5 (Three-Option OTA Update Prompt & Reminder Deferral)**:
  - Whenever an update is detected (`manifest.versionCode > BuildConfig.VERSION_CODE`), the app presents a non-blocking dialog with three explicit choices:
    1. **Update Now**: Initiates the HTTPS APK download, verifies byte size, SHA-256 digest, and `apksig` `ApkVerifier` installed-signer certificate match, locks the active vault, and launches the Android installation confirmation flow.
    2. **Update Later**: Dismisses the dialog immediately so the user can continue using the app offline without interruption.
    3. **Remind Me Later**: Opens a selector allowing the user to pick:
       - **Next app launch** (`deferUntilNextLaunch = true`)
       - **Tomorrow** (`deferUntilEpochMs = now + 24 hours`)
       - **In three days** (`deferUntilEpochMs = now + 72 hours`)
  - The reminder preference is persisted locally (alongside the target `versionCode`), suppressing automatic update prompts until the chosen condition is met. Users can still manually check and trigger **Update Now** at any time via **Settings → Updates**.
  - No APK download ever starts unless the user explicitly taps **Update Now**. Postponing, dismissing, or cancelling an update never restricts offline access to either vault.
- **Confirmed Decision 6 (Honest Physical-Device vs. Local JVM Test Reporting)**:
  - All unit and Robolectric JVM tests (cryptography vectors, Argon2id KDF, two-slot envelope isolation, record encryption at rest, backup/restore framing, `apksig` signature verification, reminder deferral logic, and Room schema migration survival) will be executed and reported with real logs.
  - Tests requiring physical Android hardware (hardware-backed Keystore StrongBox/TEE biometric prompts, OS `FLAG_SECURE` screen-capture blocking, OEM clipboard auto-clear behavior, Storage Access Framework external provider edge cases, and live Android PackageInstaller upgrade from `1.0.0` to `1.0.1`) will be clearly marked **`NOT TESTED (Requires Physical Device)`** in the handover report alongside a step-by-step owner verification script.

---

### 1. Overview & Core Concept

- **What It Does**: PRIVATE VAULT protects sensitive notes and credentials inside an authenticated AES-256-GCM encrypted local store on Android. It provides four top-level daily tools—**Notes**, **Passwords**, **Generator**, and **Strength Check**—plus an isolated **Decoy Vault** unlocked by a secondary password, portable encrypted `.pvault` manual backup/restore, and direct OTA APK updates from `https://github.com/tpeditz/Private-vault-updates`.
- **Target Audience / Persona**: Privacy-conscious Android users who require an offline vault with transparent threat boundaries, coercion resistance (Decoy Mode), local entropy/pattern password evaluation, and direct APK update verification without Play Store or cloud account dependencies.
- **Key Value**: Disciplined cryptographic isolation between Real and Decoy sessions, memory-hard Argon2id key derivation with on-device benchmark reporting, encrypted record payloads with minimal SQLite metadata exposure, `apksig`-verified OTA updates with respectful reminder controls, and verifiable data preservation across upgrades.

---

### 2. User Experience & Visual Design

- **Key User Flows**:
  1. **First-Time Vault Setup**:
     - Explains offline local storage, the necessity of a strong unique master passphrase, and that no developer backdoor or online recovery exists.
     - User creates & confirms the Real Master Password -> Atomic generation of `Slot 0` (`Real`) and `Slot 1` (`Decoy` or unconfigured dummy) versioned key envelopes.
     - Optional Decoy Vault setup (explaining decoy forensic limitations honestly, verifying `decoyPassword != realPassword`, and optionally pre-populating editable fictitious sample records using reserved domains like `example.com` / `example.org`).
     - Optional Biometric unlock setup (available **only** when Decoy Mode is disabled; automatically disabled and its Keystore wrapper wiped if Decoy Mode is enabled).
  2. **Vault Unlock & Session Routing**:
     - Master Password prompt (plus AndroidX `BiometricPrompt` bound to an Android Keystore `Cipher` when Decoy Mode is disabled).
     - Every password unlock attempt runs Argon2id against both `Slot 0` and `Slot 1` before returning, recording the measured two-vault unlock duration (`ms`) and preventing fast-fail timing leaks.
     - Entering the Real password opens `RealVaultSession`; entering the Decoy password opens `DecoyVaultSession` with identical UI quality and zero "Decoy" badges, indicators, or real-vault counts.
  3. **Four Primary Navigation Destinations** (Bottom Navigation Bar on phones / Navigation Rail on tablets + Instant Lock Action in Top App Bar):
     - **Notes**: Create, view, edit, duplicate, archive, and trash/restore notes. Supports lightweight non-executable formatting (headings, paragraphs, bullet lists, numbered lists, interactive checklists), user-created folders, tags, pinning, favorites, title/modified sorting, and active-vault local search. Features atomic encrypted autosave with explicit status (`Saving...`, `Saved`, or actionable error banner preserving in-memory draft on failure).
     - **Passwords**: Multi-account credential cards per service (stable UUID primary key, service name, account label e.g. Personal/Work, username, email, masked password, optional website URL, folder, tags, custom fields, private notes, favorite/pinned state). Provides deliberate reveal/hide with TalkBack state announcements, separate username/password copy with a 30-second auto-clearing sensitive clipboard manager, inline password generation, local strength badge, and active-vault reuse warnings.
     - **Generator**: First-class screen and reusable sheet using `java.security.SecureRandom`. Controls for length (8–64, default 20), character sets (Uppercase, Lowercase, Digits, Symbols), and excluding ambiguous characters (`0O1lI|`). Uses unbiased rejection sampling and Fisher-Yates shuffle. Rejects impossible combinations gracefully, never saves generator history, clears temporary values on lock, and provides an explicit **"Save to Passwords"** / **"Use in Credential"** action.
     - **Strength Check**: 100% offline password evaluator. Provides a 5-tier rating (`Very weak`, `Weak`, `Fair`, `Strong`, `Very strong`), concise weakness breakdown, and actionable offline suggestions. Detects dictionary words/common passwords, l33t substitutions, keyboard walks, repeated sequences, dates/years, and active-vault password reuse. Clearly states that the rating is an offline estimate and cannot check online breach databases.
  4. **Secondary Menu / Settings**:
     - **Backup & Restore**: Export/Restore `.pvault` encrypted files via Android Storage Access Framework (`CreateDocument` / `OpenDocument`) with bounded lock-window staging.
     - **Security & Decoy Settings**: Configure Auto-Lock timeout, Clipboard auto-clear timer, Screenshot protection (`FLAG_SECURE`), Master Password rotation, Biometric toggle (when Decoy is off), Argon2id KDF benchmark viewer, and Decoy Vault configuration (accessible **only** from `RealVaultSession`).
     - **Updates (OTA)**:
       - Displays installed version (`1.0.0`, code `1`), manual **Check for Updates**, automatic launch check toggle, and current reminder status.
       - When an update is available, presents the three required options: **Update Now**, **Update Later**, and **Remind Me Later** (`Next app launch`, `Tomorrow`, or `In three days`).
       - Never downloads an APK without the user choosing **Update Now**.
       - In `BuildConfig.DEBUG` builds only, provides a clearly labeled **Debug OTA Test Simulator** for testing update prompts, reminder deferrals, and `apksig` verification failure cases offline.
     - **About**: Displays exact required credits (**PRIVATE VAULT**, Developed by **Tp Editz**, Telegram: **@Tp_Editz** with copy button & confirmed external browser link to `https://t.me/Tp_Editz`), installed `versionName` and `versionCode`, concise offline privacy & threat-model disclosure, and open-source licenses.

---

### 3. Key Product Decisions & Trade-Offs

- **Decision 1: Unified Versioned Key Envelope & Encrypted Record Storage**
  - *Chosen Approach*:
    - **Envelope (`vault_envelopes`)**: Both `Slot 0` and `Slot 1` store a 72-byte AES-256-GCM `wrappedPayloadCiphertext` containing the 56-byte binary structure (`magic "PVE1"`, `slotRoleFlag`, `reservedFlags`, `createdAtEpochMs`, `rotatedAtEpochMs`, `32-byte DEK`) + 16-byte GCM authentication tag. No plaintext `isConfigured` column exists.
    - **Records (`encrypted_records`)**: Stores only `recordId` (UUID v4), `vaultSlot` (`0` or `1`), `nonce` (12 bytes), and `ciphertext` (AES-256-GCM encrypted JSON of `VaultPayload` with AAD `"PV1-REC" || vaultSlot || recordId || schemaVersion`). All titles, bodies, usernames, passwords, URLs, folders, tags, timestamps, and boolean flags (`isPinned`, `isFavorite`, `isArchived`, `isTrashed`) live inside `ciphertext`.
    - **Honest Leakage Boundary**: At rest on disk, an attacker inspecting the raw SQLite file can observe only the number of encrypted records per `vaultSlot`, approximate record byte lengths, and OS file modification timestamps.
- **Decision 2: Candidate APK Verification via Android `apksig` (`ApkVerifier`)**
  - *Chosen Approach*:
    - Adds `com.android.tools.build:apksig` to `app/build.gradle.kts`.
    - Before handing off any downloaded APK to Android's package installer, `OtaSignatureVerifier` runs `ApkVerifier.Builder(apkFile).setMinCheckedPlatformVersion(Build.VERSION.SDK_INT).build().verify()`, requires `isVerified == true`, extracts the cryptographically verified `signerCertificates`, computes their SHA-256 fingerprints, and verifies that they match the currently installed app's own signing certificate SHA-256 fingerprint from `PackageManager`.
    - Also parses `PackageManager.getPackageArchiveInfo(apkFile.absolutePath, 0)` to confirm `packageName == context.packageName` and `longVersionCode == manifest.versionCode > BuildConfig.VERSION_CODE`.
- **Decision 3: Three-Option Update Prompt & Local Reminder State Machine**
  - *Chosen Approach*:
    - `OtaReminderPreferences` stores `remindedVersionCode: Int`, `reminderMode: ReminderMode` (`NONE`, `NEXT_LAUNCH`, `TIMESTAMP`), `remindAfterEpochMs: Long`, and `launchCountAtDeferral: Long`.
    - On app launch (when automatic checks are enabled and reminder deferral allows), if a newer `versionCode` is discovered, the Update Dialog displays **Update Now**, **Update Later**, and **Remind Me Later** (`Next app launch`, `Tomorrow`, `In three days`).
    - Choosing **Update Later** dismisses the dialog for the current session. Choosing **Remind Me Later** persists the selected deferral window and suppresses automatic prompts until the next cold launch, `+24h`, or `+72h`. Opening **Settings → Updates** always allows immediate manual check and **Update Now** regardless of active reminders.

---

### 4. Technical Architecture & Data Strategy *(Technical Reference)*

- **Architecture & Component Diagram**:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MAIN ACTIVITY (FLAG_SECURE ENFORCED)                     │
│  ┌──────────────────┐  ┌─────────────────────────────────────────────────┐  │
│  │ Setup & Unlock   │  │           AUTHENTICATED VAULT SHELL             │  │
│  │  - Onboarding    │  │  TopBar: Active Tool Title | Search | Lock Now  │  │
│  │  - 2-Slot Auth   │  │  ┌──────────┬───────────┬───────────┬─────────┐ │  │
│  │  - Keystore      │  │  │  Notes   │ Passwords │ Generator │Strength │ │  │
│  │    Biometric     │  │  │   Tab    │    Tab    │    Tab    │Check Tab│ │  │
│  └────────┬─────────┘  │  └────┬─────┴─────┬─────┴─────┬─────┴────┬────┘ │  │
│           │            │       └───────────┼───────────┼──────────┘      │  │
│           │            │  Secondary: Backup/Restore | Security & KDF     │  │
│           │            │             | Updates (OTA) | About (Tp Editz)  │  │
│           │            └───────────────────┼─────────────────────────────┘  │
└───────────┼────────────────────────────────┼────────────────────────────────┘
            ▼                                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                   SESSION & CRYPTOGRAPHY ENGINE (OFFLINE)                   │
│  ┌────────────────────────────────┐  ┌───────────────────────────────────┐  │
│  │ VaultSessionManager            │  │ CryptoEngine                      │  │
│  │  - Locked                      │  │  - Argon2id (BouncyCastle 1.80)   │  │
│  │  - Unlocked(sessionId, slotId, │  │  - 2-Slot Benchmark Telemetry     │  │
│  │             dekBytes)          │  │  - AES-256-GCM (Unified 72B Env   │  │
│  │  - Lifecycle & SAF Picker Lock │  │    & AAD-Bound Record Blobs)      │  │
│  └───────────────┬────────────────┘  └─────────────────┬─────────────────┘  │
└──────────────────┼─────────────────────────────────────┼────────────────────┘
                   ▼                                     ▼
┌─────────────────────────────────────────┐  ┌────────────────────────────────┐
│   ENCRYPTED LOCAL PERSISTENCE (ROOM)    │  │  ISOLATED OTA UPDATER (HTTPS)  │
│  - VaultEnvelopeDao (Slot 0 & Slot 1)   │  │  - Endpoint: tpeditz/          │
│  - EncryptedRecordDao                   │  │    Private-vault-updates       │
│    (recordId, vaultSlot, nonce, blob)   │  │  - 3-Option Prompt & Deferral  │
│  - PortableBackupEngine (.pvault SAF)   │  │    (Now / Later / Remind:      │
│  - OfflinePasswordStrengthEstimator     │  │     Next Launch, 1d, 3d)       │
│  - SensitiveClipboardManager (30s)      │  │  - Android apksig ApkVerifier  │
│  - Explicit Non-Destructive Migrations  │  │    + Installed Signer Match    │
└─────────────────────────────────────────┘  └────────────────────────────────┘
```

- **Test & Verification Protocol**:
  - **Local JVM / Robolectric Automated Suite (`gradle :app:testDebugUnitTest`)**:
    - `CryptoAndEnvelopeTest`: Tests Argon2id determinism, two-slot unlock timing/benchmark telemetry, 72-byte unified envelope wrapping/unwrapping, GCM tag tamper rejection, atomic Master Password re-wrapping, and verifies `Slot 0` and `Slot 1` are indistinguishable in outer SQLite columns.
    - `VaultIsolationAndCrudTest`: Verifies Notes & Passwords CRUD, proves zero plaintext substrings exist in raw SQLite bytes, proves `Real` password opens only `Slot 0`, `Decoy` password opens only `Slot 1`, wrong password opens neither, and stale async jobs are cancelled on lock.
    - `GeneratorAndStrengthCheckTest`: Verifies `SecureRandom` character pool constraints, rejection of impossible combinations, and offline detection of common passwords, keyboard walks, sequences, dates, and vault-scoped reuse.
    - `PortableBackupTest`: Verifies `.pvault` encryption, tamper/wrong-password rejection, KDF bounds enforcement, cross-instance restore, and single-slot scoping.
    - `OtaUpdaterAndMigrationTest`: Verifies `update.json` parsing, 3-option reminder deferral state machine (`Next Launch`, `Tomorrow`, `In 3 Days`), `com.android.apksig.ApkVerifier` verification against valid/tampered/mismatched-signer APKs, and explicit Room database migration (`v1` -> `v2`) proving both Real and Decoy vaults survive an upgrade intact.
  - **Physical-Device Test Matrix (Reported Honestly in Documentation)**:
    - Explicitly documents `NOT TESTED (Requires Physical Device)` items for hardware StrongBox/TEE biometric invalidation, live Android PackageInstaller UI handoff (`1.0.0` -> `1.0.1`), `FLAG_SECURE` hardware display capture, and OEM clipboard overlays, with step-by-step verification instructions for the owner.
