# PRIVATE VAULT — Version 1.0.4 (`versionCode = 5`) Technical Remediation & Friendly UI/UX Redesign Plan

> [!IMPORTANT]
> **Status: PLAN REVISION ONLY — AWAITING OWNER APPROVAL.**
> No Kotlin source files, Gradle configurations, databases, resources, or CI workflows have been modified during this plan revision. Implementation will begin only after you approve this revised plan.

---

## 1. Executive Summary of the Revised Work

This revised plan unites two tightly coordinated tracks for **PRIVATE VAULT** (`applicationId = "com.tpeditz.privatevault"`, upgrading from `1.0.3` / `versionCode = 4` to `1.0.4` / `versionCode = 5`):

1. **Mandatory Security, Data-Integrity, and Release Engineering Repairs**:
   - Fixes the GitHub Actions / Gradle release-signing variable and key-alias contract (`PV-REL-001` / `PV-SEC-002`) so production builds require owner-controlled secrets and never fall back to the debug key.
   - Removes the committed `.base64` debug keystore artifact from the workspace and blocks keystore files via `.gitignore` (`PV-SEC-001` / `PV-REL-002`).
   - Hardens `.pvault` backup parsing (`PV-DATA-001`) so missing, `null`, or wrong-typed `"records"` properties are rejected as malformed before any database write, while valid empty backups (`"records": []`) require a dedicated second confirmation before `Replace`.
   - Implements backward-compatible Unicode password derivation fallback (`PV-SEC-011`), strict inner-envelope flag/reserved-byte validation (`PV-CRYPTO-001`), CSPRNG dummy slot key generation on Decoy disable (`PV-SEC-006`), proactive background auto-lock DEK wiping (`PV-SEC-007`), atomic all-or-nothing Full DEK Rekey (`PV-SEC-010`), Real/Decoy biometric settings parity (`PV-SEC-008`), and unedited-note timestamp preservation (`PV-BUG-003`).
2. **Friendly, Calm, Everyday-Usable Material 3 UI/UX Redesign**:
   - Transforms the app from a dense technical security dashboard into a welcoming, clean everyday private productivity tool.
   - Adopts the existing warm **Clean Light (`LIGHT_CLEAN`)** theme as the default for *new installations* while preserving any previously saved theme preference (`DARK_OBSIDIAN`, `LIGHT_CLEAN`, or `SYSTEM`) for existing users upgrading from prior versions.
   - Reorganizes the bottom navigation bar into four intuitive primary destinations: **Notes**, **Passwords**, **Tools** (combining *Password Generator* and *Strength Checker* under a clean segmented selector), and **Settings** (promoting *Backup & Restore*, *Security & Vault Settings*, *Appearance*, *OTA Updates*, and *About & Credits* out of the hidden overflow menu into a clear, scannable Settings hub), while keeping the one-tap **Lock Vault** action permanently visible in the top bar.

### Classification Legend Used Throughout This Plan
Every planned change is explicitly tagged with one of four classifications:
- `[REQUIRED SECURITY FIX]` — Mandatory remediation for a verified security, cryptographic, or privacy vulnerability.
- `[REQUIRED DATA-INTEGRITY FIX]` — Mandatory remediation to prevent data loss, silent corruption, or upgrade/restore failures.
- `[USER-REQUESTED UI/UX REDESIGN]` — Requested navigation, theme, visual hierarchy, and usability improvements.
- `[OPTIONAL IMPROVEMENT]` — Non-blocking quality, documentation, or defense-in-depth enhancement.

---

## 2. Verified Current Architecture and Source-File Inventory

Inspection of the active workspace confirmed the following exact architecture and file inventory:

- **Application Identity & SDKs (`app/build.gradle.kts`, `gradle/libs.versions.toml`)**:
  - `applicationId = "com.tpeditz.privatevault"` | Source `namespace = "com.example"`
  - Current version in source: `versionName = "1.0.3"`, `versionCode = 4` (Target: `versionName = "1.0.4"`, `versionCode = 5`)
  - `minSdk = 24`, `targetSdk = 36`, `compileSdk = 36 (minorApiLevel = 1)`, Java 11 bytecode target
  - AGP `9.1.1`, Kotlin `2.2.10`, KSP `2.3.5`, Room `2.7.0`, DataStore Preferences `1.1.7`, Activity Compose `1.10.1`, Fragment KTX `1.8.6`, Biometric `1.1.0`, BouncyCastle `bcprov-jdk18on:1.80`, Android `apksig:8.7.3`, OkHttp `4.10.0`, Robolectric `4.16.1`.
- **Persistence & Cryptography Layer**:
  - `PrivateVaultDatabase.kt` (Room v3, `private_vault_encrypted.db`): Contains `VaultDao`, `MIGRATION_1_2`, and `MIGRATION_2_3`. Tables: `vault_envelopes` (`slot_id` 0 and 1) and `encrypted_records` (composite primary key `PRIMARY KEY(vault_slot, record_id)`).
  - `VaultEntities.kt` & `VaultDomainModels.kt`: Defines `VaultEnvelopeEntity`, `EncryptedRecordEntity`, `NoteRecord`, `CredentialRecord`, `VaultFolder`, `ChecklistEntry`, `CustomCredentialField`, and `VaultRecordCodec` (UTF-8 JSON serializer).
  - `CryptoEngine.kt`: Implements Argon2id v1.3 (`32 MiB, t=3, p=2` standard / `16 MiB, t=4, p=2` constrained heap), 56-byte `PVE1` inner key envelope (`72-byte` AES-256-GCM ciphertext), per-record AES-256-GCM encryption, and context-bound AAD (`PV1-ENV`, `PV1-REC`, `PV1-BACKUP`).
  - `BiometricKeystoreManager.kt`: Manages Android Keystore AES-256-GCM key (`com.tpeditz.privatevault.real_bio_kek_v1`) wrapping Slot 0's DEK when Decoy Mode is disabled.
  - `VaultSessionManager.kt`: Volatile in-memory session state holder (`SessionState.Locked` vs. `SessionState.Unlocked`), generation counter (`authRequestGenerationCounter`), and SAF file-picker transition window.
  - `PortableBackupEngine.kt`: Encrypts and authenticates `.pvault` (`PVAULTB1`, 52-byte header) portable backups and implements `mergeItemsKeepNewest`.
  - `VaultRepository.kt`: Coordinates setup, dual-slot unlock, CRUD encryption, password rotation, decoy lifecycle, and backup/restore transactions.
  - `AppPreferencesRepository.kt`: DataStore Preferences (`private_vault_preferences`) storing `ThemePreference` (`DARK_OBSIDIAN`, `LIGHT_CLEAN`, `SYSTEM`), `autoLockTimeoutMs`, `lockOnScreenOff`, `blockScreenshots`, `clipboardClearTtlSeconds`, OTA reminder state, and unlock cooldown state.
- **OTA & Clipboard Utilities**:
  - `OtaUpdateManager.kt`: Performs HTTPS hop-by-hop redirect-validated manifest checks (`https://raw.githubusercontent.com/tpeditz/Private-vault-updates/main/update.json`), APK downloads, SHA-256 verification, `com.android.apksig.ApkVerifier` verification, installed signer certificate comparison, and package archive inspection.
  - `SensitiveClipboardManager.kt`: Copies secrets with `ClipDescription.EXTRA_IS_SENSITIVE`, tracks SHA-256 digest ownership, and runs a TTL auto-clear countdown.
  - `OfflinePasswordStrengthEstimator.kt` & `PasswordGeneratorEngine.kt`: Local password strength heuristic and CSPRNG password/passphrase generator.
- **UI & Presentation Layer**:
  - `MainActivity.kt`: Root `FragmentActivity`, `FLAG_SECURE` enforcement, `ACTION_SCREEN_OFF` receiver, lifecycle observer (`ON_START`/`ON_STOP`), root SAF `CreateDocument`/`OpenDocument` launchers, top app bar, bottom navigation bar (`PrimaryTab`), and OTA dialogs.
  - `VaultViewModel.kt`: Central UI state holder (`VaultUiState`), coroutines orchestration, draft management, and backup mutex coordination.
  - `SetupAndUnlockScreens.kt`: `SetupVaultScreen` and `UnlockVaultScreen`.
  - `NotesScreen.kt`: `NotesTabScreen`, `NoteItemCard`, `NoteEditorView`, `FolderManagementDialog`, and `MarkdownPreviewBlock`.
  - `PasswordsScreen.kt`: `PasswordsTabScreen`, `CredentialItemCard`, and `CredentialEditorView`.
  - `GeneratorAndStrengthScreens.kt`: `GeneratorAndStrengthScreen` and `StrengthAuditTabScreen`.
  - `SecondaryScreens.kt`: `BackupAndRestoreScreen`, `SecurityAndDecoySettingsScreen`, `OtaUpdatesScreen`, and `AboutVaultScreen`.
  - `ui/theme/Color.kt`, `Theme.kt`, `Type.kt`: Color tokens, `PrivateVaultTheme`, and bundled Google Fonts (`Plus Jakarta Sans`, `Space Grotesk`, `JetBrains Mono`).

---

## 3. Findings From Re-Checking the Existing Plan Against Source & Prior Audits (Resolving All 10 Technical Ambiguities)

1. **Offline Claim vs. OTA Accuracy (`[REQUIRED SECURITY FIX]`)**:
   - *Resolution*: All vault storage, encryption, note/password management, password generation, strength checking, and `.pvault` backup/restore operate 100% locally and offline. Network access (`android.permission.INTERNET`) is used solely for optional GitHub OTA update checks and APK downloads. All UI copy, About text, and documentation will state this accurately: *"All vault data stays encrypted on your device. Internet access is used only when checking for or downloading app updates."*
2. **Unicode Password Normalization Without Breaking Existing Vaults (`[REQUIRED DATA-INTEGRITY FIX]`)**:
   - *Problem*: Applying `Normalizer.Form.NFC` unconditionally in `CryptoEngine.charArrayToUtf8Bytes()` would cause an existing vault or `.pvault` backup created with a non-ASCII unnormalized (e.g., NFD) password to derive a different 256-bit KEK and fail to unlock!
   - *Resolution*:
     - Preserve raw UTF-8 encoding (`charArrayToUtf8BytesRaw`) as the primary derivation path for existing v1 envelopes and `.pvault` backups.
     - During **Unlock** (`VaultRepository.unlockWithPassword`) and **Backup Restore/Preview** (`PortableBackupEngine.decryptAndVerifyBackupBytes`): if the password contains any non-ASCII character (`chars.any { it.code > 0x7F }`) and NFC normalization produces a different char sequence than the raw input, first attempt unwrap using the **NFC-normalized** form; if AEAD tag verification fails (`null` / `AEADBadTagException`), automatically retry unwrap on that same slot/header using the **raw unnormalized** form!
     - During **New Vault Setup**, **Password Change**, and **New Backup Creation**: normalize non-ASCII passwords to NFC before deriving the key. When an existing vault unlocks via the legacy raw non-NFC fallback, silently re-wrap its envelope under the NFC-normalized KEK on next password change. Pure ASCII passwords (`code <= 0x7F`) are byte-for-byte identical under NFC and never trigger a second KDF pass.
3. **Full DEK Compromise-Recovery Rekey Boundaries & Rollback (`[REQUIRED SECURITY FIX]`)**:
   - *Exact Scope*: Rekeys every `EncryptedRecordEntity` belonging to the active `vault_slot` (all `NoteRecord`s, `CredentialRecord`s, and custom `VaultFolder`s) plus the active slot's `VaultEnvelopeEntity`, and invalidates/clears any Slot 0 biometric wrapper (`biometricNonce = null, biometricWrappedDek = null`). Slot 1 records (if in Slot 0) or Slot 0 records (if in Slot 1) are never touched.
   - *Staging, Verification & Rollback*:
     1. Acquire `kdfMutex` and verify the user's current password against the active slot envelope.
     2. Load all existing `EncryptedRecordEntity` rows for `activeSlot`. Decrypt and authenticate every single row into memory using the current DEK. **If even one record fails AEAD authentication (`corruptedCount > 0`), abort immediately before generating a new DEK or touching SQLite**, and inform the user so no unreadable ciphertext is ever lost or half-migrated.
     3. Generate a fresh 32-byte `newDek` via `SecureRandom`, re-encrypt every record in memory with a fresh 12-byte random nonce and matching `PV1-REC` AAD, and decrypt-verify each new ciphertext in memory.
     4. Derive `newKek` from the new password + fresh 16-byte salt, and wrap `newDek` into `updatedEnvelope` (clearing biometric fields if Slot 0).
     5. Execute a single Room `@Transaction` (`vaultDao.rekeySlotAtomically(updatedEnvelope, reEncryptedRecords)`) that updates the envelope and replaces the slot's record ciphertexts in one atomic SQLite commit. If the process crashes or throws before transaction commit, SQLite rolls back completely to the previous DEK and ciphertexts.
     6. Only after the SQLite transaction succeeds, update the in-memory `VaultSession` with `newDek` and zero the old `dekBytes`, `oldKek`, and `newKek`.
4. **Auto-Lock Lifecycle State Machine (`[REQUIRED SECURITY FIX]`)**:
   - *Exact Behavior Across All Transitions*:
     - **Configuration Change / Screen Rotation (`activity.isChangingConfigurations == true`)**: Never locks the vault, never cancels active drafts, and keeps session state in `VaultViewModel`.
     - **Screen Off (`Intent.ACTION_SCREEN_OFF`)**: If `lockOnScreenOff == true`, immediately cancels any pending SAF picker grant window, zeroes the in-memory DEK, clears owned clipboard data, deletes any uncommitted staged backup file, and transitions to `SessionState.Locked`.
     - **Leaving App (`ON_STOP` when `!isChangingConfigurations`)**:
       - **Case A — Normal App Switch / Home Button (Not in SAF Picker Window)**:
         - If `autoLockTimeoutMs == 0L` (*Immediate*): Calls `lockVaultNow()` immediately inside `ON_STOP`, wiping the DEK and plaintext UI state before the activity finishes stopping.
         - If `autoLockTimeoutMs > 0L` (*15s, 1m, 5m*): Records `lastBackgroundedAtMonotonicMs` AND starts a coroutine `backgroundAutoLockJob` in `viewModelScope` that sleeps for `autoLockTimeoutMs` and then calls `lockVaultNow()` while still in the background. If OS doze suspends the coroutine, `ON_START` (`onAppForegrounded`) checks `monotonicClockMs() - lastBackgroundedAtMonotonicMs >= autoLockTimeoutMs` and locks immediately before rendering a single unlocked frame.
       - **Case B — External SAF Picker / Permission Activity Launched**:
         - Launching `CreateDocument` or `OpenDocument` opens a bounded 90-second `FILE_PICKER_GRANT_WINDOW_MS` bound to `(sessionId, slotId)`.
         - While `ON_STOP` occurs during this window, the vault stays unlocked for up to 90 seconds so the user can pick a file. A background coroutine timer set to `90_000L` ensures that if the user abandons the phone with the SAF picker open for >90 seconds, the vault automatically locks in the background and deletes the staged `.pvault` file!
         - Staged `.pvault` files are deleted ONLY inside `completeExportToUri`'s `finally` block (after the file copy completes or fails), on explicit cancellation, or when the 90-second picker timeout expires—never prematurely while the user is still choosing a folder.
     - **External Installer / Browser Handoff (OTA Install, Unknown Sources Settings, Telegram/Instagram Links)**: Explicitly calls `lockVaultNow()` *before* `startActivity(...)`.
     - **Process Death**: Because DEKs and session states live strictly in volatile RAM (`VaultSessionManager`) and never in `SavedInstanceState`, process recreation always starts cleanly at `UnlockVaultScreen`.
5. **Backup Scope Filtering Without Dangling References (`[REQUIRED DATA-INTEGRITY FIX]`)**:
   - `ALL_DATA`: Exports all `NoteRecord`s, `CredentialRecord`s, and custom `VaultFolder`s in the active slot.
   - `NOTES_ONLY`: Exports only `NoteRecord`s and `VaultFolder`s where `scope == FolderScope.NOTES`. Every exported `NoteRecord.folderId` is validated against the exported `NOTES` folders (or mapped to `DEFAULT_NOTE_FOLDER_ID` `"General"` if its folder was missing) before serialization so zero dangling folder references can exist.
   - `PASSWORDS_ONLY`: Exports only `CredentialRecord`s and `VaultFolder`s where `scope == FolderScope.CREDENTIALS`, validating every `CredentialRecord.folderId` against the exported `CREDENTIALS` folders.
   - Furthermore, when restoring a `NOTES_ONLY` or `PASSWORDS_ONLY` backup in `REPLACE_ACTIVE_VAULT` mode, the UI clearly warns that `Replace` replaces the entire active vault with the contents of the backup (and recommends `Merge` when importing a partial section backup into a vault that has both notes and passwords).
6. **Release Signing Contract & Installed Signer Continuity (`[REQUIRED SECURITY FIX]`)**:
   - Unifies `app/build.gradle.kts` and `.github/workflows/publish-ota.yml` on `PV_RELEASE_STORE_FILE`, `PV_RELEASE_STORE_PASSWORD`, `PV_RELEASE_KEY_ALIAS`, and `PV_RELEASE_KEY_PASSWORD` (with fallback to AI Studio's `KEYSTORE_PATH`, `STORE_PASSWORD`, `KEY_ALIAS`, `KEY_PASSWORD`).
   - Production release builds fail fast in CI if any secret, keystore file, or expected production signer fingerprint (`EXPECTED_PRODUCTION_CERT_SHA256`) is missing or mismatches.
7. **Evidence-Based R8 Minification (`[OPTIONAL IMPROVEMENT / HARDENING]`)**:
   - Enables `isMinifyEnabled = true` on `release` with targeted, verified keep rules in `app/proguard-rules.pro` strictly for classes accessed via reflection/JNI/serialization: Room `@Entity` and `PrivateVaultDatabase_Impl` constructors, BouncyCastle `org.bouncycastle.crypto.generators.Argon2BytesGenerator` and JCA provider classes, and `com.android.apksig.**`.
8. **Version, Schema, and Theme Preference Continuity (`[REQUIRED DATA-INTEGRITY FIX]`)**:
   - Keeps `applicationId = "com.tpeditz.privatevault"` and Room schema `version = 3` (`MIGRATION_1_2`, `MIGRATION_2_3`).
   - Theme default rule: In `AppPreferencesRepository.preferencesFlow`, `prefs[KEY_THEME]` returns `null` **only** when the user has never saved a theme preference (or on a fresh install). By changing the fallback expression `prefs[KEY_THEME] ?: ThemePreference.LIGHT_CLEAN.name` (and setting `VaultAppPreferences(themePreference = ThemePreference.LIGHT_CLEAN)`), brand-new installations open in the friendly Light theme, whereas any existing user who previously selected `DARK_OBSIDIAN`, `LIGHT_CLEAN`, or `SYSTEM` retains their stored `KEY_THEME` value untouched!
9. **Real / Decoy Indistinguishability (`[REQUIRED SECURITY FIX]`)**:
   - Unifies the Biometric Quick-Unlock settings card across Slot 0 (with Decoy enabled) and Slot 1 (Decoy session) so both display the identical status message (`"Biometric unlock is unavailable under the current vault policy"`), and replaces the hardcoded `'x'` dummy password in `disableDecoyVault()` with CSPRNG random key bytes.
10. **Honest Separation of Test Evidence (`[REQUIRED DATA-INTEGRITY FIX]`)**:
    - Distinguishes existing tests, new JVM/Robolectric tests executed in the build container, and physical-device/production-secret checks that cannot be simulated in a headless container.

---

## 4. Final Product Navigation Map and User Journeys (`[USER-REQUESTED UI/UX REDESIGN]`)

### 4.1 Consolidated 4-Tab Navigation Architecture

Instead of splitting closely related password utilities across two bottom tabs and hiding Settings/Backup inside a 3-dot overflow menu, the unlocked app shell uses **four clear bottom navigation destinations** plus a persistent top-bar **Lock Vault** button:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ Top App Bar: [Shield Icon] Private Vault              [Lock Vault Button 🔒] │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                         Active Screen Content Area                           │
│                                                                              │
├──────────────────┬──────────────────┬──────────────────┬─────────────────────┤
│  📝 Notes        │  🔑 Passwords    │  🛠️ Tools        │  ⚙️ Settings        │
│  (PrimaryTab.    │  (PrimaryTab.    │  (PrimaryTab.    │  (PrimaryTab.       │
│   NOTES)         │   PASSWORDS)     │   TOOLS)         │   SETTINGS)         │
└──────────────────┴──────────────────┴──────────────────┴─────────────────────┘
```

- **Tab 1 — Notes (`PrimaryTab.NOTES`)**: Search bar, folder & status filter chips (`All`, `Favorites`, `Archive`, `Trash`, plus custom folders), clean note cards, and a `+ New Note` Floating Action Button. Opening a note launches the full-screen distraction-free **Note Editor** (hiding the bottom bar for maximum writing space).
- **Tab 2 — Passwords (`PrimaryTab.PASSWORDS`)**: Search bar, folder & status filter chips (`All`, `Favorites`, `Archive`, `Trash`, plus custom folders), scannable credential cards with one-tap Masked Copy / Reveal, and an `+ Add Password` Floating Action Button. Opening an item launches the full-screen **Password Editor**.
- **Tab 3 — Tools (`PrimaryTab.TOOLS`)**: Contains a clean 2-option segmented switcher at the top:
  - **Segment A — Password Generator**: Unbiased random password & passphrase generator with plain-language controls, Show/Hide toggle, Copy, and **"Use in New Password"** button (which jumps straight into the Password Editor pre-filled with the generated secret).
  - **Segment B — Strength Checker**: Masked password input with Show/Hide toggle, plain-language strength badge, actionable improvement tips, and an optional expandable *"Technical details"* section for entropy bits.
- **Tab 4 — Settings (`PrimaryTab.SETTINGS`)**: A clean, grouped Settings hub with plain-language cards/rows that open dedicated sub-screens (`SecondaryDestination`):
  1. **Backup & Restore** (`Export or restore encrypted .pvault files`) — Placed first so users can back up effortlessly.
  2. **Appearance** (`Light`, `Dark`, or `System Default` segmented theme selector directly accessible).
  3. **Security & Auto-Lock** (`Change vault password, biometric unlock, auto-lock timer, screen security, and advanced envelope policy`).
  4. **App Updates (OTA)** (`Check for updates, automatic check toggle, and verification status`).
  5. **About & Credits** (`Version 1.0.4 (Code 5), offline privacy summary, and Tp Editz contact links`).

---

## 5. Complete Design System (`[USER-REQUESTED UI/UX REDESIGN]`)

### 5.1 Theme Modes & Color Tokens (`Color.kt` & `Theme.kt`)
- **Default Theme Behavior**:
  - New installs default to **Clean Light (`ThemePreference.LIGHT_CLEAN`)**.
  - Users can switch at any time between **Light**, **Dark**, and **System Default** inside `Settings → Appearance`. Existing saved preferences in DataStore are preserved across app updates.
- **Light Theme Palette (`LIGHT_CLEAN` — Warm, Calm Everyday Productivity)**:
  - `background`: `#F8FAFC` (Soft Warm Alabaster)
  - `surface`: `#FFFFFF` (Crisp Pure White for cards and sheets)
  - `surfaceVariant`: `#EEF2F6` (Subtle Slate Tint for search bars, chips, and grouped rows)
  - `onBackground` / `onSurface`: `#0F172A` (Deep Slate Ink — WCAG AAA contrast `17.4:1` on white)
  - `onSurfaceVariant`: `#475569` (Muted Slate for subtitles and metadata — WCAG AA `7.5:1` on white)
  - `primary`: `#047857` (Restrained Forest Emerald) | `onPrimary`: `#FFFFFF`
  - `primaryContainer`: `#D1FAE5` (Soft Mint Pill Indicator) | `onPrimaryContainer`: `#064E3B`
  - `outline`: `#CBD5E1` (Clean 1 dp hairline border)
  - `error`: `#DC2626` (Reserved strictly for errors and destructive confirmations)
- **Dark Theme Palette (`DARK_OBSIDIAN` — Calm Low-Glare Night Mode)**:
  - `background`: `#0B0F19` (Deep Obsidian Slate)
  - `surface`: `#111827` (Elevated Charcoal Surface)
  - `surfaceVariant`: `#1E293B` (Muted Slate Container)
  - `onBackground` / `onSurface`: `#F1F5F9` (Crisp Off-White — `16.8:1` contrast)
  - `onSurfaceVariant`: `#94A3B8` (Readable Secondary Slate — `6.4:1` contrast)
  - `primary`: `#10B981` (Balanced Emerald) | `onPrimary`: `#002114`
  - `primaryContainer`: `#064E3B` | `onPrimaryContainer`: `#A7F3D0`
  - `outline`: `#334155`
  - `error`: `#EF4444`

### 5.2 Typography Hierarchy (`Type.kt`)
- **Primary UI Font (`PlusJakartaSansFontFamily`)**: Used for all everyday screen titles, card titles, body copy, form labels, buttons, and helper descriptions so the app reads like a modern consumer note/password app rather than a sci-fi terminal.
- **Display Header Font (`SpaceGroteskFontFamily`)**: Reserved only for large onboarding/unlock welcome headers (`headlineLarge`, `displayMedium`).
- **Monospace Font (`JetBrainsMonoFontFamily`)**: Reserved strictly for passwords, generated secrets, SHA-256 fingerprints, and numeric countdown badges.

### 5.3 Spacing, Shapes, Icons, and Component Rules
- **8 dp Grid System**:
  - Screen horizontal padding: `16.dp` (compact phones) / `24.dp` (tablets/expanded `>= 640.dp` centered with `widthIn(max = 680.dp)`).
  - Card internal padding: `16.dp`.
  - Vertical gap between list cards: `10.dp`.
  - Section spacing in forms/settings: `16.dp`.
- **Shape Tokens (`VaultShapes`)**:
  - Text fields & small chips: `10.dp` (`RoundedCornerShape(10.dp)`).
  - Cards & settings groups: `14.dp` (`RoundedCornerShape(14.dp)`).
  - Dialogs & bottom sheets: `20.dp` (`RoundedCornerShape(20.dp)`).
- **Touch Targets & Controls**:
  - Every `IconButton`, `FilterChip`, `Switch`, and action button enforces at least `48.dp x 48.dp` interactive touch area.
  - Card actions avoid icon clutter: each Note or Password card shows at most 1–2 primary quick actions (e.g., Copy / Reveal on Passwords) plus a clean `More (⋮)` menu for secondary actions (`Favorite`, `Pin`, `Duplicate`, `Archive`, `Move to Trash`).

---

## 6. Screen-by-Screen UI Redesign Specification & Text Wireframes (`[USER-REQUESTED UI/UX REDESIGN]`)

### A. Notes Screen (`NotesScreen.kt`)
- **Above the Fold**:
  - Top bar with app title and one-tap **Lock Vault** icon button (`contentDescription = "Lock vault now"`).
  - Full-width rounded Search bar (`"Search notes…"`), with a Sort button (`Recently Updated`, `Newest`, `A–Z`) and Folder Manage icon button (`Folders`).
  - Single horizontal scrollable row of filter chips: `All`, `Favorites`, `Archive`, `Trash`, followed by user-created folders.
  - Clean vertical list of Note cards (`title`, 2-line plain preview, folder pill, relative date, and a `⋮` item menu for *Pin*, *Favorite*, *Duplicate*, *Archive*, and *Move to Trash*).
  - Bottom-right `+ New Note` Floating Action Button.
- **Empty State**: Centered illustration icon, friendly heading (`"No notes yet"` or `"No matching notes"`), short subtitle (`"Write private notes, checklists, or ideas. Everything stays encrypted on your phone."`), and a primary `"Create your first note"` button.

```
┌──────────────────────────────────────────────────────────┐
│ 🛡️ Private Vault                                  [🔒]  │
├──────────────────────────────────────────────────────────┤
│ [ 🔍 Search notes...                          ] [⇅] [📁] │
│ ( All ) ( ★ Favorites ) ( Archive ) ( Trash ) ( Work )   │
├──────────────────────────────────────────────────────────┤
│ ┌──────────────────────────────────────────────────────┐ │
│ │ 📌 Home Wi-Fi & Router Setup                    [⋮]  │ │
│ │ Living room router admin steps and guest network...  │ │
│ │ 📁 Personal  •  Updated 10m ago                      │ │
│ └──────────────────────────────────────────────────────┘ │
│ ┌──────────────────────────────────────────────────────┐ │
│ │ Grocery & Weekend Errands                       [⋮]  │ │
│ │ ☑ Renew passport photos  ☐ Pick up parcel            │ │
│ │ 📁 General   •  Yesterday                            │ │
│ └──────────────────────────────────────────────────────┘ │
│                                           ( + New Note ) │
├─────────────┬──────────────┬──────────────┬──────────────┤
│  📝 Notes   │ 🔑 Passwords │   🛠️ Tools   │ ⚙️ Settings  │
└─────────────┴──────────────┴──────────────┴──────────────┘
```

### B. Note Editor (`NoteEditorView` in `NotesScreen.kt`)
- **Above the Fold**:
  - Distraction-free top bar: `[← Back]` button on the left, live quiet **Autosave status badge** in the center (`"Saved"`, `"Saving…"`, `"Unsaved changes"`, or `"Save failed"`), and `[📌 Pin]`, `[★ Favorite]`, `[⋮ More (Duplicate / Archive / Move to Trash)]`, plus `[Save & Done]` on the right.
  - Mode selector pill row: `Plain Text`, `Formatted / Markdown`, `Checklist`, plus Folder & Category selector chips.
  - When `Formatted / Markdown` is selected: a simple formatting helper bar (`H1`, `Bold`, `• Bullet`, `1. Numbered`, `Preview Toggle`) so users do not need to memorize Markdown syntax, plus full rendering of headings, bullets, and numbered lists (`1. `, `2. `).
  - Large, comfortable Title field and multi-line Body writing area (`KeyboardOptions(autoCorrectEnabled = false)`).
  - Bottom navigation bar is hidden so the keyboard never crowds the writing area.

```
┌──────────────────────────────────────────────────────────┐
│ [←]  ● Saved                              [📌] [⋮] [Done]│
├──────────────────────────────────────────────────────────┤
│ ( Plain Text ) ( Formatted ) ( Checklist )   [📁 General]│
│ [ H1 ] [ B ] [ • List ] [ 1. List ]          [👁 Preview]│
├──────────────────────────────────────────────────────────┤
│ Note title                                               │
│ ──────────────────────────────────────────────────────── │
│ Write your note here...                                  │
│ 1. First numbered step                                   │
│ 2. Second numbered step                                  │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### C. Passwords Screen (`PasswordsScreen.kt`)
- **Above the Fold**:
  - Full-width Search bar (`"Search saved passwords, usernames, or labels…"`), with Sort button and Folder Manage button.
  - Filter chip row: `All`, `Favorites`, `Archive`, `Trash`, and custom credential folders.
  - Scannable Credential cards showing:
    - **Service / Entry Name** (bold) + optional **Account Label badge** (e.g., `Personal`, `Work`).
    - **Username / Email** subtitle.
    - Masked password row (`••••••••••••`) with explicit `[👁 Reveal]`, `[📋 Copy Password]`, and `[⋮ More]` buttons (`Copy Username`, `Duplicate`, `Archive`, `Move to Trash`).
  - Bottom-right `+ Add Password` Floating Action Button.

```
┌──────────────────────────────────────────────────────────┐
│ 🛡️ Private Vault                                  [🔒]  │
├──────────────────────────────────────────────────────────┤
│ [ 🔍 Search passwords, usernames, labels...   ] [⇅] [📁] │
│ ( All ) ( ★ Favorites ) ( Archive ) ( Trash ) ( Banking )│
├──────────────────────────────────────────────────────────┤
│ ┌──────────────────────────────────────────────────────┐ │
│ │ GitHub                               [Work]     [⋮]  │ │
│ │ parveez@example.com                                  │ │
│ │ Password: ••••••••••••        [👁 Show] [📋 Copy]    │ │
│ └──────────────────────────────────────────────────────┘ │
│                                       ( + Add Password ) │
├─────────────┬──────────────┬──────────────┬──────────────┤
│  📝 Notes   │ 🔑 Passwords │   🛠️ Tools   │ ⚙️ Settings  │
└─────────────┴──────────────┴──────────────┴──────────────┘
```

### D. Password Editor (`CredentialEditorView` in `PasswordsScreen.kt`)
- **Logical Field Grouping**:
  1. **Account Identity**: `Service or Website Name *`, `Account Label (e.g., Personal, Work)`, and `Username or Email`.
  2. **Secret Password**: Masked `Password *` input (`KeyboardType.Password`, `autoCorrectEnabled = false`) with `[👁 Show/Hide]` toggle and an inline **`[🎲 Generate Strong Password]`** button right below the field, accompanied by a calm reminder: *"Updating a password here updates your vault—remember to also change it on the website or app."*
  3. **Details & Custom Fields**: `Website URL`, `Folder`, `Notes`, and `Custom Fields` (each with a `Secret (mask value)` checkbox).

### E. Tools Screen (`GeneratorAndStrengthScreens.kt`)
- **Consolidated Segmented Header**:
  - Top segmented control: **`[ Password Generator ]`** | **`[ Strength Checker ]`**.
- **Segment 1 — Password Generator**:
  - Masked/Revealed candidate display card (`JetBrains Mono`) with `[👁 Show/Hide]`, `[📋 Copy]`, and a prominent **`[＋ Use in New Saved Password]`** button.
  - Plain-language strength badge (e.g., `"Strong"` / `"Very Strong"`) and a concise 1-line summary (`"20 characters • Uppercase, lowercase, numbers & symbols"`).
  - Simple controls: Length slider (`8–64`), 4 clear character-group switches (`Uppercase A–Z`, `Lowercase a–z`, `Numbers 0–9`, `Symbols !@#`), `Avoid look-alike characters (O/0, l/1)`, and a Passphrase section with word-count chips (`4`, `5`, `6`, `7`, `8` words).
  - If all 4 character switches are turned off, shows an immediate friendly message: *"Turn on at least one character type to generate a password."*
- **Segment 2 — Strength Checker**:
  - Masked password input field by default (`PasswordVisualTransformation()`, `KeyboardType.Password`, `autoCorrectEnabled = false`) with `[👁 Show/Hide]` button.
  - Plain-language rating card (`Very Weak` to `Very Strong`) + clear bulleted improvement suggestions.
  - Clear offline disclosure card: *"Checked privately on your phone. Because Private Vault works offline, it does not send passwords to online breach databases."*
  - Expandable `"Show technical details"` row for users who want to see character pool size and estimated bits.

```
┌──────────────────────────────────────────────────────────┐
│ 🛡️ Private Vault                                  [🔒]  │
├──────────────────────────────────────────────────────────┤
│ [ ● Password Generator ]      [ ○ Strength Checker ]     │
├──────────────────────────────────────────────────────────┤
│ ┌──────────────────────────────────────────────────────┐ │
│ │  k9#mP4$vL2@nQ8!zR5&w                    [👁] [📋]   │ │
│ │  ● Very Strong  •  20 characters                     │ │
│ │  [ 🔄 New Password ]   [ ＋ Use in Saved Password ]  │ │
│ └──────────────────────────────────────────────────────┘ │
│ Length: 20 characters       [─────────●────────]         │
│ [✓] Uppercase (A-Z)         [✓] Lowercase (a-z)          │
│ [✓] Numbers (0-9)           [✓] Symbols (!@#$)           │
│ [✓] Avoid look-alike characters (0/O, 1/l)               │
│ ──────────────────────────────────────────────────────── │
│ Or generate a multi-word passphrase:                     │
│ Words: ( 4 ) ( ● 5 ) ( 6 ) ( 7 ) ( 8 )  [ Generate ]     │
├─────────────┬──────────────┬──────────────┬──────────────┤
│  📝 Notes   │ 🔑 Passwords │   🛠️ Tools   │ ⚙️ Settings  │
└─────────────┴──────────────┴──────────────┴──────────────┘
```

### F. Settings Hub Screen (`SecondaryScreens.kt`)
- **Above the Fold**:
  - **Backup & Restore Card (Highlighted at Top)**: `"Export an encrypted .pvault backup file or restore from a previous backup."` → Opens `BackupAndRestoreScreen`.
  - **Appearance Section**: Inline 3-segment selector for **`Light`**, **`Dark`**, and **`System`** theme preferences.
  - **Security & Auto-Lock Row**: `"Vault password, biometric unlock, auto-lock timer, and privacy protection."` → Opens `SecurityAndDecoySettingsScreen`.
  - **App Updates (OTA) Row**: `"Version 1.0.4 • Check for updates or manage automatic checks."` → Opens `OtaUpdatesScreen`.
  - **About & Developer Credits Row**: `"Offline architecture details and Tp Editz links."` → Opens `AboutVaultScreen`.
  - Calm footer note: *"Your vault is encrypted with your password. Because there is no cloud account, forgetting your password means your data cannot be recovered without a backup."*

### G. Backup & Restore Screen (`BackupAndRestoreScreen` in `SecondaryScreens.kt`)
- **Step-by-Step Export Card**:
  1. **What to include**: Filter chips for `All Vault Data`, `Notes Only`, `Passwords Only`.
  2. **Backup Password**: Masked password + confirm password fields (`KeyboardType.Password`, `autoCorrectEnabled = false`).
  3. **Action**: `[Create Encrypted Backup (.pvault)]` button + live stage banner (`Preparing encrypted backup…` → `Choose where to save…` → `Backup saved (14 KB).`).
- **Step-by-Step Restore Card**:
  1. `[1. Select .pvault Backup File]` → Displays selected file name.
  2. **Backup Password**: Masked password field.
  3. **Verify & Preview**: `[2. Verify & Preview Contents]` button → Decrypts and validates in memory, displaying a verified summary card (`Notes: X • Passwords: Y • Folders: Z • Backup Version: 1`).
  4. **Restore Mode Choice (Plain-Language Radio Cards)**:
     - **Merge with current vault (Recommended)**: *"Keeps your existing items and adds or updates items from the backup."*
     - **Replace current vault**: *"Deletes all items currently in this vault and replaces them with the backup."* (If the verified backup contains `0` records, selecting `Replace` triggers a mandatory confirmation dialog warning that the vault will become completely empty).

```
┌──────────────────────────────────────────────────────────┐
│ [←] Backup & Restore                               [🔒]  │
├──────────────────────────────────────────────────────────┤
│ EXPORT BACKUP (.PVAULT)                                  │
│ Include: ( ● All Data ) ( Notes Only ) ( Passwords Only )│
│ [ Backup password                             [👁] ]     │
│ [ Confirm backup password                     [👁] ]     │
│ [        Create Encrypted Backup (.pvault)         ]     │
├──────────────────────────────────────────────────────────┤
│ RESTORE FROM BACKUP                                      │
│ Selected: vault_backup_2026.pvault        [Change File]  │
│ [ Enter backup password                       [👁] ]     │
│ [ 1. Verify & Preview ]                                  │
│ ┌──────────────────────────────────────────────────────┐ │
│ │ ✓ Verified Backup  •  12 Notes, 8 Passwords          │ │
│ │ (●) Merge (Recommended) — Keep existing & add newer  │ │
│ │ ( ) Replace — Erase current vault & use backup only  │ │
│ │ [            2. Restore Backup Now                 ] │ │
│ └──────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

### H. Security, Biometric & Auto-Lock Screen (`SecurityAndDecoySettingsScreen`)
- Grouped into clear sections:
  1. **Auto-Lock & Privacy**: Auto-lock timeout chips (`Immediate`, `15 seconds`, `1 minute`, `5 minutes`), `Lock when screen turns off` switch, `Block screenshots & recents preview` switch, and `Auto-clear copied passwords` timer (`15s`, `30s`, `60s`).
  2. **Biometric Unlock**: Plain-language explanation (*"Use your fingerprint or face to unlock the vault without typing your password every time. Your master password is still required after a restart or policy change."*). Shows accurate Keystore backing status without unverified StrongBox claims, and renders the exact same policy state in both Real (with Decoy active) and Decoy sessions.
  3. **Change Vault Password**: Current password, new password, confirm new password, plus an expandable advanced option: **`[ ] Also generate a new encryption key and re-encrypt all items (use if an old backup or device was exposed)`**.
  4. **Advanced Multi-Envelope Policy**: Gated behind password verification with identical neutral phrasing in all sessions.

### I. Setup & Unlock Screens (`SetupAndUnlockScreens.kt`)
- **First-Time Setup**: Calm, welcoming Light-default layout explaining clearly: *"Choose a strong vault password. Private Vault does not use cloud accounts—if you forget your password, we cannot reset it for you."* Includes show/hide toggles, live strength feedback, and an optional expandable section for configuring a secondary vault envelope.
- **Unlock Screen**: Clean password field (`KeyboardType.Password`, `autoCorrectEnabled = false`), show/hide toggle, primary `Unlock Vault` button, and a `Use Biometrics` button when enrolled. Error messages distinguish wrong password from corrupted storage without hinting whether a secondary vault exists.

### J. OTA Updates & About Screens (`SecondaryScreens.kt`)
- **OTA Updates**: Displays installed version (`1.0.4 (Code 5)`), a toggle for **`Check for updates automatically on app launch`**, a `[Check for Updates Now]` button, and clear download progress with a **`[Cancel Download]`** button. Explains clearly that update checks use HTTPS to GitHub while vault records remain 100% local.
- **About & Credits**: Displays `PRIVATE VAULT`, `Version 1.0.4 (Code 5)`, `Developed by Tp Editz`, and confirmation-guarded links for Telegram (`@Tp_Editz`) and Instagram (`@tp_ediitz`) that lock the vault before opening an external browser/app.

---

## 7. Accessibility and Responsive-Layout Requirements (`[USER-REQUESTED UI/UX REDESIGN]`)

- **Minimum 48 dp Touch Targets**: Enforced on all icon buttons, visibility toggles, filter chips, segmented buttons, and menu triggers.
- **TalkBack Semantic Descriptions**: Every icon-only control declares an explicit action description (e.g., `"Lock vault immediately"`, `"Show password"`, `"Hide password"`, `"Copy password to clipboard"`, `"More actions for note"`). Password values are never read aloud by TalkBack while masked.
- **Font Scaling & Long Text Resilience**: Layouts use flexible `Row`/`Column`/`FlowRow` containers and `sp` typography so 130%–200% Android font scaling, multi-line note titles, Arabic/Indic RTL text, and narrow screens (`< 360.dp`) never clip buttons or overlap text.
- **Non-Blocking Feedback**: Routine confirmations (`"Saved"`, `"Copied"`, `"Moved to Trash"`) use the non-blocking status banner, whereas destructive actions (`Delete Permanently`, `Replace Active Vault`, `Empty Vault Replace`) use explicit modal `AlertDialog` confirmations.

---

## 8. Security and Data-Preservation Constraints Governing the Redesign

The UI redesign strictly obeys the following non-negotiable rules:
1. `applicationId` remains `"com.tpeditz.privatevault"` and source `namespace` remains `"com.example"`.
2. Room SQLite schema version 3 (`vault_envelopes` and `encrypted_records`) and migrations `MIGRATION_1_2` and `MIGRATION_2_3` remain completely intact.
3. All search, filtering (`All`, `Favorites`, `Archive`, `Trash`, folders), and sorting operate strictly in volatile memory over the active unlocked session's decrypted list—never writing plaintext search indexes to SQLite or disk.
4. `FLAG_SECURE` remains enforced at all times while locked and whenever `blockScreenshots` is enabled (and cannot be disabled from a Decoy session).
5. Secret values (passwords, secret custom fields, strength checker input) remain masked by default, never appear in notification previews or logs, and disable IME personalized dictionary learning (`autoCorrectEnabled = false`, `KeyboardType.Password`).

---

## 9. Technical Remediation Plan (Classified by Requirement Type)

| ID | Component | Classification | Exact Technical Remediation |
| :--- | :--- | :--- | :--- |
| **PV-REL-001 / PV-SEC-002** | `app/build.gradle.kts`, `.github/workflows/publish-ota.yml` | `[REQUIRED SECURITY FIX]` | Unify the release signing contract so `app/build.gradle.kts` reads `PV_RELEASE_STORE_FILE` (or `KEYSTORE_PATH`), `PV_RELEASE_STORE_PASSWORD` (or `STORE_PASSWORD`), `PV_RELEASE_KEY_ALIAS` (or `KEY_ALIAS`, never hardcoded to `"upload"` when secret is provided), and `PV_RELEASE_KEY_PASSWORD` (or `KEY_PASSWORD`). Add CI pre-publish checks verifying APK signature, package name, `versionCode`, and expected production signer SHA-256. |
| **PV-SEC-001 / PV-REL-002** | `.aistudio/.../debug.keystore.base64`, `.gitignore`, `.github/workflows/*.yml` | `[REQUIRED SECURITY FIX]` | Delete `.aistudio/artifacts/brain/2a19f8cf-e32e-491f-8c69-a22bba937042/debug.keystore.base64`, add `*.keystore`, `*.jks`, `*.p12`, `*.keystore.base64` to `.gitignore`, and remove the committed-file fallback from CI workflows so CI relies only on GitHub Actions Secrets. |
| **PV-DATA-001** | `PortableBackupEngine.kt`, `SecondaryScreens.kt` | `[REQUIRED DATA-INTEGRITY FIX]` | Replace `root.optJSONArray("records") ?: JSONArray()` with strict validation requiring `root.has("records") && !root.isNull("records") && root.get("records") is JSONArray`. Validate every element, ID uniqueness, field length, and folder reference before any DB write. Add a second confirmation dialog when a valid backup has `records: []` (`0` items) and `Replace` is selected. |
| **PV-BUILD-001** | `gradlew`, `gradlew.bat`, `gradle/wrapper/` | `[REQUIRED DATA-INTEGRITY FIX]` | Generate and commit the official Gradle 9.3.1 wrapper scripts and `gradle-wrapper.jar` so `./gradlew` builds work cleanly from any checkout. |
| **PV-CRYPTO-001** | `CryptoEngine.kt` | `[REQUIRED SECURITY FIX]` | In `unwrapEnvelopePayloadOrNull`, strictly validate `roleFlag in setOf(SLOT_ROLE_DUMMY, SLOT_ROLE_ACTIVE)`, `decoyPolicyFlag in setOf(DECOY_POLICY_DISABLED, DECOY_POLICY_ENABLED)`, and reserved bytes `r0 == 0.toByte() && r1 == 0.toByte()`, returning `null` on any invalid byte. |
| **PV-SEC-006** | `VaultRepository.kt` | `[REQUIRED SECURITY FIX]` | Replace hardcoded `CharArray(16) { 'x' }` in `disableDecoyVault()` (and dummy slot init) with 32 bytes of CSPRNG output (`CryptoEngine.randomBytes(32)`) so no password can unwrap a dummy Slot 1 envelope. |
| **PV-SEC-007 & PV-BACKUP-001** | `VaultViewModel.kt`, `VaultSessionManager.kt` | `[REQUIRED SECURITY FIX]` | Lock immediately on `ON_STOP` when `autoLockTimeoutMs == 0L` (outside SAF picker window), schedule a background coroutine timer for non-zero timeouts that wipes the DEK and cleans up expired staged files in the background, and report explicit status feedback if `backupMutex.tryLock()` is contended. |
| **PV-SEC-008** | `VaultViewModel.kt`, `SecondaryScreens.kt` | `[REQUIRED SECURITY FIX]` | Add `isBiometricBlockedByPolicy` to `VaultUiState` (true in both Slot 0 with Decoy enabled and Slot 1) so the Biometric settings card is 100% identical in Real and Decoy sessions. |
| **PV-SEC-003 / PV-BUG-002** | `PasswordGeneratorEngine.kt`, `OfflinePasswordStrengthEstimator.kt`, `VaultViewModel.kt` | `[REQUIRED SECURITY FIX]` | Route all password/passphrase generation through unbiased `PasswordGeneratorEngine.nextUnbiasedInt()`, surface `InvalidConfig` when all character classes are turned off, and compute realistic word-list entropy for passphrases in `OfflinePasswordStrengthEstimator`. |
| **PV-SEC-004** | `GeneratorAndStrengthScreens.kt`, `NotesScreen.kt`, `PasswordsScreen.kt`, `SecondaryScreens.kt` | `[REQUIRED SECURITY FIX]` | Mask `strengthCheckerInput` by default with Show/Hide toggle, set `KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false)` on all password/secret fields, and set `KeyboardOptions(autoCorrectEnabled = false)` on note/credential editors. |
| **PV-SEC-005 & PV-SEC-001 (Audit 1)** | `BiometricKeystoreManager.kt` | `[REQUIRED SECURITY FIX]` | Add explicit `setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)` on API 30+ (and `setUserAuthenticationValidityDurationSeconds(-1)` on API 24–29), rename `hasHardwareKey()` to `hasKeystoreKey()`, and query `KeyInfo` on API 23+/31+ to report hardware backing accurately. |
| **PV-SEC-011** | `CryptoEngine.kt`, `VaultRepository.kt`, `PortableBackupEngine.kt` | `[REQUIRED DATA-INTEGRITY FIX]` | Normalize non-ASCII passwords to Unicode NFC for new derivations while providing automatic raw-UTF-8 fallback retry during unlock and backup restore for existing non-ASCII passwords. |
| **PV-SEC-009 & PV-SEC-010** | `VaultRepository.kt`, `PrivateVaultDatabase.kt`, `SecondaryScreens.kt` | `[OPTIONAL IMPROVEMENT]` | Keep default `"General"` folders virtual in memory unless modified so SQLite `record_id` contains only UUIDs, and add an atomic `rekeyAllRecordsWithNewDek` option when changing a vault password. |
| **PV-BUG-003 & PV-BUG-004** | `VaultViewModel.kt`, `NotesScreen.kt` | `[REQUIRED DATA-INTEGRITY FIX]` | Track `isDirty: Boolean` and `AutosaveIndicator` on `NoteEditorDraftState` so viewing an existing note without editing never triggers autosave or overwrites `updatedAtEpochMs`. |
| **PV-BUG-006, 007, 008, 009, 010** | `VaultDomainModels.kt`, `NotesScreen.kt`, `PasswordsScreen.kt`, `SecondaryScreens.kt` | `[USER-REQUESTED UI/UX REDESIGN]` | Add confirmation dialogs before permanent delete, add `accountLabel` and `isArchived` (with safe JSON defaults), add Duplicate/Archive actions, render numbered lists in Markdown preview, add Backup Export scope chips (`All`, `Notes Only`, `Passwords Only`), and add Startup OTA Check toggle + Download Cancel button. |
| **PV-SEC-012 & PV-DOC-001** | `app/build.gradle.kts`, `proguard-rules.pro`, `PRIVATE_VAULT_ARCHITECTURE_AND_HANDOVER.md` | `[OPTIONAL IMPROVEMENT]` | Enable `isMinifyEnabled = true` on `release` with verified keep rules, remove unused `navigation-compose`, set `versionCode = 5` / `versionName = "1.0.4"`, and synchronize handover documentation. |

---

## 10. Version, Database, Backup Migration & Rollback Plan

1. **Application Version & Package Continuity**:
   - `applicationId` stays `"com.tpeditz.privatevault"`.
   - `versionCode` increments from `4` to `5`; `versionName` increments from `"1.0.3"` to `"1.0.4"`.
2. **Database Schema Compatibility (`PrivateVaultDatabase` v3)**:
   - The Room SQLite schema remains at **Version 3** (`vault_envelopes` and `encrypted_records` with composite primary key `(vault_slot, record_id)`).
   - Existing migrations `MIGRATION_1_2` and `MIGRATION_2_3` are preserved unchanged, and `fallbackToDestructiveMigration()` remains strictly prohibited.
   - New domain fields (`NoteRecord.isArchived`, `CredentialRecord.isArchived`, `CredentialRecord.accountLabel`) are serialized inside the encrypted JSON payload using backward-compatible `root.optBoolean("isArchived", false)` and `root.optString("accountLabel", "")` defaults in `VaultRecordCodec`. All v1.0.0–v1.0.3 encrypted records decrypt seamlessly without requiring a SQLite table migration.
3. **Password & Envelope Compatibility**:
   - Existing v1 key envelopes (`PVE1`, 72 bytes) unlock without modification because valid envelopes produced by v1.0.0–v1.0.3 already set `slotRoleFlag in {0, 1}`, `decoyPolicyFlag in {0, 1}`, and reserved bytes `0x00, 0x00`.
   - Existing non-ASCII passwords continue to unlock via the automatic NFC-then-raw fallback in `CryptoEngine`.
4. **Safe Upgrade & Rollback Procedure for Existing Users**:
   - Before installing v1.0.4 (`versionCode = 5`), users on v1.0.3 can optionally export a `.pvault` backup.
   - Because v1.0.4 uses the same `.pvault` `PVAULTB1` header and `backupSchemaVersion = 1`, backups created in v1.0.1–v1.0.3 restore cleanly into v1.0.4, and backups created in v1.0.4 remain readable by v1.0.3 (with any new optional JSON keys ignored by older `JSONObject.opt*` readers).

---

## 11. Exact Files, Classes, and Functions Expected to Change

### Group 1 — Security, Cryptography & Data-Integrity Layer
1. `/app/src/main/java/com/example/security/CryptoEngine.kt`:
   - `unwrapEnvelopePayloadOrNull`: Enforce strict validation of `roleFlag`, `decoyPolicyFlag`, and zeroed reserved bytes (`PV-CRYPTO-001`).
   - `deriveKeyArgon2id` & `charArrayToUtf8Bytes`: Add Unicode NFC normalization with `deriveKeyArgon2idRawLegacy` helper for non-ASCII fallback (`PV-SEC-011`).
2. `/app/src/main/java/com/example/security/BiometricKeystoreManager.kt`:
   - `getEncryptCipherForEnrollment`: Add explicit `setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)` on API 30+ and `setUserAuthenticationValidityDurationSeconds(-1)` on API 24–29 (`PV-SEC-005`).
   - Rename `hasHardwareKey()` to `hasKeystoreKey()` and add `isHardwareBackedKey()` using `KeyFactory` / `KeyInfo` (`PV-SEC-001`).
3. `/app/src/main/java/com/example/security/PasswordGeneratorEngine.kt` & `/app/src/main/java/com/example/security/OfflinePasswordStrengthEstimator.kt`:
   - Unify password and passphrase generation on `PasswordGeneratorEngine.nextUnbiasedInt()` and add passphrase word-list entropy detection in `OfflinePasswordStrengthEstimator.evaluate()` (`PV-SEC-003`, `PV-QUALITY-001`).
4. `/app/src/main/java/com/example/data/VaultDomainModels.kt`:
   - Add `isArchived: Boolean = false` to `NoteRecord` and `CredentialRecord`, and `accountLabel: String = ""` to `CredentialRecord` (`PV-BUG-007`).
5. `/app/src/main/java/com/example/data/PortableBackupEngine.kt`:
   - Add `enum class BackupExportScope { ALL_DATA, NOTES_ONLY, PASSWORDS_ONLY }` (`PV-BUG-009`).
   - In `decryptAndVerifyBackupBytes`: Enforce strict `root.has("records") && !root.isNull("records") && root.get("records") is JSONArray` validation, validate folder references, and support non-ASCII NFC/raw password fallback (`PV-DATA-001`, `PV-SEC-011`).
6. `/app/src/main/java/com/example/data/PrivateVaultDatabase.kt`:
   - Add `@Transaction suspend fun rekeySlotAtomically(updatedEnvelope: VaultEnvelopeEntity, reEncryptedRecords: List<EncryptedRecordEntity>)` in `VaultDao` (`PV-SEC-010`).
7. `/app/src/main/java/com/example/data/VaultRepository.kt`:
   - `unlockWithPassword`: Support automatic non-ASCII NFC-then-raw fallback (`PV-SEC-011`).
   - `disableDecoyVault` & `initializeNewVault`: Use 32-byte CSPRNG random key for dummy Slot 1 (`PV-SEC-006`).
   - `changeActiveVaultPassword`: Support atomic `rekeyAllRecordsWithNewDek: Boolean = false` (`PV-SEC-010`).
   - `prepareEncryptedBackupBytes`: Filter items and folders cleanly by `BackupExportScope` (`PV-BUG-009`).
   - Keep built-in `"General"` folders virtual in memory unless modified (`PV-SEC-009`).
8. `/app/src/main/java/com/example/data/AppPreferencesRepository.kt`:
   - Default `ThemePreference` fallback on fresh installs (when `KEY_THEME` is absent) to `ThemePreference.LIGHT_CLEAN` while preserving any saved preference.
   - Add `autoCheckOtaOnStartup: Boolean = true` preference (`PV-BUG-010`).
9. `/app/src/main/java/com/example/ota/OtaUpdateManager.kt`:
   - Support cancellable in-flight download tracking and cleanup of partial APK files (`PV-BUG-010`).

### Group 2 — UI, Navigation & ViewModel Layer
10. `/app/src/main/java/com/example/ui/VaultViewModel.kt`:
    - Update `PrimaryTab` (`NOTES`, `PASSWORDS`, `TOOLS`, `SETTINGS`) and add `ToolsSegment` (`GENERATOR`, `STRENGTH_CHECKER`).
    - Implement proactive `backgroundAutoLockJob` in `onAppBackgrounded()` (`PV-SEC-007`).
    - Report explicit user feedback if `backupMutex.tryLock()` is contended (`PV-BACKUP-001`).
    - Add `isBiometricBlockedByPolicy` (`PV-SEC-008`), `isDirty` & `AutosaveIndicator` on `NoteEditorDraftState` (`PV-BUG-003`, `PV-BUG-004`), `duplicateNote`, `duplicateCredential`, `toggleNoteArchive`, `toggleCredentialArchive`, `useGeneratedPasswordInNewCredential`, and `cancelOtaDownload`.
11. `/app/src/main/java/com/example/MainActivity.kt`:
    - Update bottom `NavigationBar` / `NavigationRail` to the 4 friendly destinations (`Notes`, `Passwords`, `Tools`, `Settings`) while keeping the prominent top-bar **Lock Vault** action and locked OTA status dialog (`cancelDownload` wired).
12. `/app/src/main/java/com/example/ui/NotesScreen.kt`:
    - Redesign `NotesTabScreen`, `NoteItemCard`, and `NoteEditorView` with `isDirty`-guarded autosave, live `AutosaveIndicator` badge, formatting toolbar + numbered-list Markdown preview (`PV-BUG-008`), `Archive` filter chip, `Duplicate` action, permanent-delete confirmation `AlertDialog` (`PV-BUG-006`), and `KeyboardOptions(autoCorrectEnabled = false)` (`PV-SEC-004`).
13. `/app/src/main/java/com/example/ui/PasswordsScreen.kt`:
    - Redesign `PasswordsTabScreen`, `CredentialItemCard`, and `CredentialEditorView` with `accountLabel` field/badge (`PV-BUG-007`), `Archive` filter chip, `Duplicate` action, permanent-delete confirmation `AlertDialog` (`PV-BUG-006`), external-service password update reminder (`PV-BUG-011`), and `KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false)` (`PV-SEC-004`).
14. `/app/src/main/java/com/example/ui/GeneratorAndStrengthScreens.kt`:
    - Combine into the unified **Tools** screen with a segmented switcher (`Password Generator` | `Strength Checker`), Show/Hide toggles on both generator output and strength checker input, `"Use in New Saved Password"` button, 4–8 word passphrase chips, offline breach disclosure, and expandable technical entropy details (`PV-SEC-003`, `PV-SEC-004`, `PV-BUG-005`, `PV-BUG-011`, `PV-QUALITY-001`).
15. `/app/src/main/java/com/example/ui/SecondaryScreens.kt`:
    - Add `SettingsHubScreen` as the primary view for `PrimaryTab.SETTINGS`.
    - Update `BackupAndRestoreScreen` with export scope chips (`All Data`, `Notes Only`, `Passwords Only`), plain-language Merge vs. Replace cards, and an explicit confirmation dialog before replacing with a valid empty (`0`-record) backup (`PV-DATA-001`, `PV-BUG-009`).
    - Update `SecurityAndDecoySettingsScreen` with indistinguishable biometric policy status (`PV-SEC-008`), accurate Keystore backing labels (`PV-SEC-001`), and the optional Full DEK Rekey checkbox (`PV-SEC-010`).
    - Update `OtaUpdatesScreen` with the `autoCheckOtaOnStartup` switch and `Cancel Download` button (`PV-BUG-010`).
16. `/app/src/main/java/com/example/ui/SetupAndUnlockScreens.kt` & `/app/src/main/java/com/example/ui/theme/Theme.kt`:
    - Refine Setup and Unlock screens for the warm Light default aesthetic with clear password-recovery warnings and `KeyboardType.Password` privacy flags.

### Group 3 — Build, Release Signing, Wrapper & Documentation Files
17. `/app/build.gradle.kts` & `/app/proguard-rules.pro`:
    - Bump `versionCode = 5` and `versionName = "1.0.4"`.
    - Unify `release` signing config to read `PV_RELEASE_*` / `KEYSTORE_PATH` env vars and dynamic `keyAlias` (`PV-REL-001` / `PV-SEC-002`).
    - Enable `isMinifyEnabled = true` on `release` (`PV-SEC-012`) and remove unused `navigation-compose` (`PV-BUG-014`).
18. `/.github/workflows/publish-ota.yml`, `/.github/workflows/build-apk.yml`, `/.gitignore`:
    - Remove `.base64` repo fallback, add pre-publish APK signature & expected certificate SHA-256 verification, and update `.gitignore` (`PV-SEC-001`, `PV-REL-001`, `PV-REL-002`).
    - Delete `/.aistudio/artifacts/brain/2a19f8cf-e32e-491f-8c69-a22bba937042/debug.keystore.base64`.
19. `/gradlew`, `/gradlew.bat`, `/gradle/wrapper/gradle-wrapper.jar`:
    - Generate and commit the official Gradle 9.3.1 wrapper files (`PV-BUILD-001`).
20. `/PRIVATE_VAULT_ARCHITECTURE_AND_HANDOVER.md`:
    - Synchronize version metadata to `1.0.4` (`versionCode = 5`) and document SQLite metadata & decoy boundaries (`PV-DOC-001`, `PV-PRIV-001`).

### Group 4 — Automated Regression Tests
21. `/app/src/test/java/com/example/ExampleRobolectricTest.kt`:
    - Expand the Robolectric test suite with dedicated tests for `PV-DATA-001`, `PV-CRYPTO-001`, `PV-SEC-003`, `PV-SEC-006`, `PV-SEC-007`, `PV-SEC-008`, `PV-SEC-010`, `PV-SEC-011`, `PV-BACKUP-001`, and `PV-BUG-003`.

---

## 12. Risk Analysis and Dependencies Between Changes

1. **Unicode Normalization vs. Existing Non-ASCII Vaults**:
   - *Risk*: Changing `charArrayToUtf8Bytes` without a fallback would lock out existing users with non-ASCII passwords.
   - *Mitigation*: Implement the dual-try NFC-then-raw fallback in `unlockWithPassword` and `decryptAndVerifyBackupBytes`, verified by unit tests before any UI changes.
2. **R8 Minification vs. Room / BouncyCastle / Compose**:
   - *Risk*: Over-aggressive shrinking could strip Room DAO implementations or BouncyCastle JCA providers in `release` builds.
   - *Mitigation*: Verify `proguard-rules.pro` by running `gradle :app:assembleRelease` (with a temporary local test keystore) and inspecting the R8 output and APK contents.
3. **Navigation Consolidation (`PrimaryTab.TOOLS` and `PrimaryTab.SETTINGS`) vs. Existing Test Tags**:
   - *Risk*: Automated tests or deep state transitions referencing old tab enum values could break.
   - *Mitigation*: Update `VaultViewModel` navigation helpers cleanly and preserve semantic `testTag` identifiers on all core buttons and inputs.

---

## 13. Regression and Acceptance Test Matrix

| Test Category & ID | What Is Verified | Test Type | Current Status |
| :--- | :--- | :--- | :--- |
| **Existing Suite (`T01`–`T31`)** | SAF 32-bit requestCode (`fragment:1.8.6`), `.pvault` round-trip, backup preview, cross-slot guard, biometric invalidation fallback, clipboard TTL, decoy parity, v1->v2->v3 migrations, OTA hop-by-hop redirect & `apksig` verification | Automated JVM / Robolectric (`ExampleRobolectricTest`) | **EXISTING (12/12 PASS in v1.0.3)** |
| **New `RT-DATA-001`** | Malformed `.pvault` payloads (`missing` `records`, `records: null`, `records: "string"`, `records: {}`, `records: 123`, array with `null`/malformed elements, duplicate IDs, invalid folder links) are rejected before any DB mutation; active & inactive slots remain byte-for-byte unchanged; valid `records: []` is flagged as empty backup | Automated JVM / Robolectric | **PLANNED (To Be Added & Executed)** |
| **New `RT-CRYPTO-001`** | `CryptoEngine.unwrapEnvelopePayloadOrNull` rejects invalid `slotRoleFlag`, invalid `decoyPolicyFlag`, and non-zero reserved bytes (`r0 != 0 || r1 != 0`) | Automated JVM / Robolectric | **PLANNED (To Be Added & Executed)** |
| **New `RT-SEC-006`** | `disableDecoyVault()` uses CSPRNG random key material and cannot be unwrapped with `"xxxxxxxxxxxxxxxx"` | Automated JVM / Robolectric | **PLANNED (To Be Added & Executed)** |
| **New `RT-SEC-007`** | `viewModel.onAppBackgrounded()` locks immediately when `autoLockTimeoutMs == 0L` (outside SAF picker window) and wipes `dekBytes` in background without waiting for `onAppForegrounded()` | Automated JVM / Robolectric | **PLANNED (To Be Added & Executed)** |
| **New `RT-SEC-008`** | Decoy session (`slotId = 1`) sets `isBiometricBlockedByPolicy = true`, matching Slot 0 when Decoy Mode is enabled | Automated JVM / Robolectric | **PLANNED (To Be Added & Executed)** |
| **New `RT-SEC-003`** | `PasswordGeneratorEngine` rejects all-off character switches with `generatorError`, and `OfflinePasswordStrengthEstimator` calculates realistic word-list entropy for passphrases | Automated JVM / Robolectric | **PLANNED (To Be Added & Executed)** |
| **New `RT-SEC-010`** | `changeActiveVaultPassword(..., rekeyAllRecordsWithNewDek = true)` generates a new 256-bit DEK and atomically re-encrypts all active-slot records while preserving the inactive slot | Automated JVM / Robolectric | **PLANNED (To Be Added & Executed)** |
| **New `RT-SEC-011`** | Composed (`\u00E9`) and decomposed (`e\u0301`) passwords derive the same NFC key on new vaults, and legacy unnormalized non-ASCII vaults still unlock via automatic fallback | Automated JVM / Robolectric | **PLANNED (To Be Added & Executed)** |
| **New `RT-BUG-003 & BACKUP-001`** | Opening an existing note without edits keeps `isDirty = false` and preserves `updatedAtEpochMs`; overlapping `completeExportToUri` calls report clear contention status | Automated JVM / Robolectric | **PLANNED (To Be Added & Executed)** |
| **Device & Production Signer Verification (`T32`)** | Physical Realme 11 Pro+ / Android 15 SAF Save As / Open picker round-trip, OEM keyboard inset behavior, hardware TEE biometric prompt, and live production signer continuity check against the user's installed APK | Physical Android Device & Owner Release Keystore | **REQUIRES PHYSICAL DEVICE & OWNER KEY** |

---

## 14. Build & Test Commands and Required Evidence

During implementation, the following commands will be executed in the workspace and their actual outputs reported:
1. `./gradlew --version` — Confirms the committed Gradle 9.3.1 wrapper executes cleanly.
2. `./gradlew :app:testDebugUnitTest --no-daemon` — Executes all existing and newly added unit/Robolectric tests (`RT-DATA-001` through `RT-BUG-003`). Must exit `0` with `BUILD SUCCESSFUL`.
3. `./gradlew :app:assembleDebug --no-daemon` and `compile_applet` — Verifies clean compilation and resource packaging of the redesigned v1.0.4 (`versionCode = 5`) app.
4. `./gradlew :app:dependencyInsight --dependency org.bouncycastle:bcprov-jdk18on --configuration releaseRuntimeClasspath --no-daemon` — Documents the resolved cryptographic and networking dependency graph.
5. APK Metadata & Signature Verification via `keytool -printcert -jarfile` and Python `apksig`/SHA-256 inspection — Reports exact file size, SHA-256 hash, `versionCode = 5`, `versionName = "1.0.4"`, and certificate fingerprint.

---

## 15. Explicit Out-of-Scope Items and Assumptions Requiring Owner Approval

1. **No Cloud Sync, Accounts, or Online Breach APIs**: Strictly out of scope to preserve local offline privacy.
2. **No SQLCipher Full-Database Encryption Migration in v1.0.4**: Per audit requirement, replacing standard Room SQLite with SQLCipher would break in-place database compatibility without a multi-stage migration; record payloads and envelopes remain AES-256-GCM encrypted with AAD binding, and SQLite metadata boundaries are transparently documented.
3. **Production Signing Certificate Continuity**: Because the container does not have access to your phone's installed APK or your private GitHub Actions Secrets, CI workflows will be configured to require your production keystore secrets and verify `EXPECTED_PRODUCTION_CERT_SHA256` before publishing any OTA release.

---

## 16. Implementation Sequence (Small, Reviewable Phases)

Once you approve this plan:
- **Phase 1 — Build Reproducibility & Release Signing Hardening**: Restore the Gradle 9.3.1 wrapper, remove the committed `.base64` keystore artifact, update `.gitignore`, and unify the Gradle + GitHub Actions signing contract (`PV-REL-001`, `PV-SEC-001`, `PV-SEC-002`, `PV-BUILD-001`).
- **Phase 2 — Core Cryptography, Strict Backup Parser & Repository Hardening**: Implement strict `.pvault` `"records"` array validation (`PV-DATA-001`), inner-envelope flag/reserved-byte validation (`PV-CRYPTO-001`), CSPRNG dummy slot keys (`PV-SEC-006`), backward-compatible Unicode NFC fallback (`PV-SEC-011`), Keystore auth parameters & accurate hardware reporting (`PV-SEC-005`, `PV-SEC-001`), unbiased generator & passphrase entropy (`PV-SEC-003`, `PV-QUALITY-001`), virtual default folders (`PV-SEC-009`), and atomic Full DEK Rekey (`PV-SEC-010`).
- **Phase 3 — ViewModel Lifecycle, Auto-Lock & Draft State Machine**: Implement proactive background auto-lock (`PV-SEC-007`), backup mutex feedback (`PV-BACKUP-001`), Real/Decoy biometric policy parity (`PV-SEC-008`), `isDirty` note autosave tracking (`PV-BUG-003`, `PV-BUG-004`), and 4-tab navigation state (`Notes`, `Passwords`, `Tools`, `Settings`).
- **Phase 4 — Friendly Light-Default UI/UX Redesign Across All Screens**: Update `AppPreferencesRepository` default theme for new installs to `LIGHT_CLEAN`, redesign `MainActivity`, `NotesScreen`, `PasswordsScreen`, `GeneratorAndStrengthScreens` (`Tools`), `SecondaryScreens` (`Settings Hub`, `Backup & Restore`, `Security`, `OTA`, `About`), and `SetupAndUnlockScreens` with full keyboard privacy flags (`PV-SEC-004`) and confirmation dialogs (`PV-BUG-006`).
- **Phase 5 — R8 Verification & Automated Regression Test Suite**: Configure and verify R8 keep rules (`PV-SEC-012`), add all new regression tests in `ExampleRobolectricTest.kt`, run the full build and test suite, and deliver the verified engineering report.
