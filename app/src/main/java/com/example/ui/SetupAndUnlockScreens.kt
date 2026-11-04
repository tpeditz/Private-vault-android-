package com.example.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.example.security.OfflinePasswordStrengthEstimator
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.theme.StatusFair
import com.example.ui.theme.StatusStrong
import com.example.ui.theme.StatusVeryStrong
import com.example.ui.theme.StatusVeryWeak
import com.example.ui.theme.StatusWeak

@Composable
fun SetupVaultScreen(
    uiState: VaultUiState,
    onCompleteSetup: (
        masterPassword: String,
        confirmMasterPassword: String,
        enableDecoy: Boolean,
        decoyPassword: String,
        confirmDecoyPassword: String,
        seedSampleDecoyData: Boolean
    ) -> Unit
) {
    var masterPassword by remember { mutableStateOf("") }
    var confirmMasterPassword by remember { mutableStateOf("") }
    var showMasterPassword by remember { mutableStateOf(false) }

    var enableDecoy by remember { mutableStateOf(false) }
    var decoyPassword by remember { mutableStateOf("") }
    var confirmDecoyPassword by remember { mutableStateOf("") }
    var showDecoyPassword by remember { mutableStateOf(false) }
    var seedSampleDecoyData by remember { mutableStateOf(true) }
    var acknowledgedNoReset by remember { mutableStateOf(false) }

    val strengthReport = remember(masterPassword) {
        OfflinePasswordStrengthEstimator.evaluate(masterPassword)
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .imePadding(),
        contentAlignment = Alignment.TopCenter
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .widthIn(max = 560.dp)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 28.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Box(
                    modifier = Modifier
                        .size(52.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.primaryContainer),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Filled.Shield,
                        contentDescription = "Private Vault Security Shield",
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(28.dp)
                    )
                }
                Column {
                    Text(
                        text = "PRIVATE VAULT",
                        style = MaterialTheme.typography.headlineLarge,
                        color = MaterialTheme.colorScheme.onBackground
                    )
                    Text(
                        text = "Offline Encrypted Storage • Zero Cloud Backdoors",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
            }

            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.65f)
                )
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.VerifiedUser,
                            contentDescription = "Encryption boundary info",
                            tint = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = "How Your Vault Is Protected",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                    Text(
                        text = "• All notes, credentials, folders, and timestamps are encrypted locally on your device with AES-256-GCM.\n" +
                            "• Your master passphrase derives your key using memory-hard Argon2id (RFC 9106) and is never stored or transmitted.\n" +
                            "• There is NO developer backdoor and NO online password reset. If you forget your master password without an encrypted backup, your vault cannot be recovered.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            // Master Password Section
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = "1. Create Real Master Password",
                        style = MaterialTheme.typography.titleMedium
                    )

                    OutlinedTextField(
                        value = masterPassword,
                        onValueChange = { masterPassword = it },
                        label = { Text("Master Password (min 8 chars, 16+ recommended)") },
                        singleLine = true,
                        visualTransformation = if (showMasterPassword) VisualTransformation.None else PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(
                            capitalization = KeyboardCapitalization.None,
                            autoCorrectEnabled = false,
                            keyboardType = KeyboardType.Password,
                            imeAction = ImeAction.Next
                        ),
                        trailingIcon = {
                            IconButton(
                                onClick = { showMasterPassword = !showMasterPassword },
                                modifier = Modifier.semantics {
                                    contentDescription = if (showMasterPassword) {
                                        "Master password visible. Tap to hide."
                                    } else {
                                        "Master password hidden. Tap to reveal."
                                    }
                                }
                            ) {
                                Icon(
                                    imageVector = if (showMasterPassword) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                    contentDescription = null
                                )
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("setup_master_password_input")
                    )

                    if (masterPassword.isNotEmpty()) {
                        val barColor = when (strengthReport.rating) {
                            OfflinePasswordStrengthEstimator.StrengthRating.VERY_WEAK -> StatusVeryWeak
                            OfflinePasswordStrengthEstimator.StrengthRating.WEAK -> StatusWeak
                            OfflinePasswordStrengthEstimator.StrengthRating.FAIR -> StatusFair
                            OfflinePasswordStrengthEstimator.StrengthRating.STRONG -> StatusStrong
                            OfflinePasswordStrengthEstimator.StrengthRating.VERY_STRONG -> StatusVeryStrong
                        }
                        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(
                                    text = "Offline Strength: ${strengthReport.rating.label}",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = barColor
                                )
                                Text(
                                    text = "~${strengthReport.effectiveEntropyBits.toInt()} bits",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = JetBrainsMonoFontFamily
                                )
                            }
                            LinearProgressIndicator(
                                progress = { (strengthReport.scoreOutOf100 / 100f).coerceIn(0.05f, 1f) },
                                color = barColor,
                                modifier = Modifier.fillMaxWidth()
                            )
                        }
                    }

                    OutlinedTextField(
                        value = confirmMasterPassword,
                        onValueChange = { confirmMasterPassword = it },
                        label = { Text("Confirm Master Password") },
                        singleLine = true,
                        visualTransformation = if (showMasterPassword) VisualTransformation.None else PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(
                            capitalization = KeyboardCapitalization.None,
                            autoCorrectEnabled = false,
                            keyboardType = KeyboardType.Password,
                            imeAction = ImeAction.Done
                        ),
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("setup_confirm_master_password_input")
                    )
                }
            }

            // Optional Decoy Vault Setup
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "2. Optional Fake / Decoy Vault",
                                style = MaterialTheme.typography.titleMedium
                            )
                            Text(
                                text = "Configure a separate password that opens an isolated secondary vault.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(
                            checked = enableDecoy,
                            onCheckedChange = { enableDecoy = it },
                            modifier = Modifier.testTag("setup_enable_decoy_switch")
                        )
                    }

                    if (enableDecoy) {
                        HorizontalDivider()
                        Surface(
                            color = MaterialTheme.colorScheme.surfaceVariant,
                            shape = MaterialTheme.shapes.small
                        ) {
                            Row(
                                modifier = Modifier.padding(12.dp),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Icon(
                                    imageVector = Icons.Outlined.Info,
                                    contentDescription = "Decoy limitations notice",
                                    tint = MaterialTheme.colorScheme.secondary,
                                    modifier = Modifier.size(20.dp)
                                )
                                Text(
                                    text = "Decoy Privacy & Limitations: Entering the decoy password opens only the decoy vault with zero visual indicators. While Decoy Mode is enabled, biometric unlock for the real vault is disabled. Note: Decoy isolation protects against casual inspection, but forensic analysis of storage size or app specifications may still indicate that decoy support exists.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }

                        OutlinedTextField(
                            value = decoyPassword,
                            onValueChange = { decoyPassword = it },
                            label = { Text("Decoy Password (must differ from Real Password)") },
                            singleLine = true,
                            visualTransformation = if (showDecoyPassword) VisualTransformation.None else PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(
                                capitalization = KeyboardCapitalization.None,
                                autoCorrectEnabled = false,
                                keyboardType = KeyboardType.Password,
                                imeAction = ImeAction.Next
                            ),
                            trailingIcon = {
                                IconButton(onClick = { showDecoyPassword = !showDecoyPassword }) {
                                    Icon(
                                        imageVector = if (showDecoyPassword) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                        contentDescription = if (showDecoyPassword) "Hide decoy password" else "Reveal decoy password"
                                    )
                                }
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("setup_decoy_password_input")
                        )

                        OutlinedTextField(
                            value = confirmDecoyPassword,
                            onValueChange = { confirmDecoyPassword = it },
                            label = { Text("Confirm Decoy Password") },
                            singleLine = true,
                            visualTransformation = if (showDecoyPassword) VisualTransformation.None else PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(
                                capitalization = KeyboardCapitalization.None,
                                autoCorrectEnabled = false,
                                keyboardType = KeyboardType.Password,
                                imeAction = ImeAction.Done
                            ),
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("setup_confirm_decoy_password_input")
                        )

                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Checkbox(
                                checked = seedSampleDecoyData,
                                onCheckedChange = { seedSampleDecoyData = it },
                                modifier = Modifier.testTag("setup_seed_decoy_checkbox")
                            )
                            Text(
                                text = "Pre-populate harmless sample notes & fictitious accounts (example.org) in Decoy Vault",
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
                }
            }

            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Checkbox(
                    checked = acknowledgedNoReset,
                    onCheckedChange = { acknowledgedNoReset = it },
                    modifier = Modifier.testTag("setup_acknowledge_checkbox")
                )
                Text(
                    text = "I understand that PRIVATE VAULT is 100% offline and there is no online password recovery.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onBackground
                )
            }

            if (uiState.unlockErrorMessage != null) {
                Surface(
                    color = MaterialTheme.colorScheme.errorContainer,
                    shape = MaterialTheme.shapes.small,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = uiState.unlockErrorMessage,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(12.dp)
                    )
                }
            }

            Button(
                onClick = {
                    onCompleteSetup(
                        masterPassword,
                        confirmMasterPassword,
                        enableDecoy,
                        decoyPassword,
                        confirmDecoyPassword,
                        seedSampleDecoyData
                    )
                },
                enabled = !uiState.isUnlockInProgress && acknowledgedNoReset && masterPassword.length >= 8,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(54.dp)
                    .testTag("setup_initialize_vault_button")
            ) {
                if (uiState.isUnlockInProgress) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(22.dp),
                        color = MaterialTheme.colorScheme.onPrimary,
                        strokeWidth = 2.dp
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Text("Deriving Argon2id Keys & Sealing Envelopes...")
                } else {
                    Icon(imageVector = Icons.Filled.Lock, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Initialize Encrypted Vault")
                }
            }
        }
    }
}

@Composable
fun UnlockVaultScreen(
    uiState: VaultUiState,
    onUnlockWithPassword: (String) -> Unit,
    onTriggerBiometricUnlock: () -> Unit
) {
    var password by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }

    val isLockedOut = uiState.unlockBackoffRemainingMs > 0L

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .imePadding(),
        contentAlignment = Alignment.Center
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .widthIn(max = 460.dp)
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(20.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(72.dp)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.primaryContainer),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Filled.Security,
                    contentDescription = "Vault Locked",
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(36.dp)
                )
            }

            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    text = "PRIVATE VAULT",
                    style = MaterialTheme.typography.headlineLarge,
                    color = MaterialTheme.colorScheme.onBackground
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Enter your master password to decrypt and unlock your session.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    OutlinedTextField(
                        value = password,
                        onValueChange = { password = it },
                        label = { Text("Master Password") },
                        singleLine = true,
                        enabled = !uiState.isUnlockInProgress && !isLockedOut,
                        visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(
                            capitalization = KeyboardCapitalization.None,
                            autoCorrectEnabled = false,
                            keyboardType = KeyboardType.Password,
                            imeAction = ImeAction.Done
                        ),
                        keyboardActions = KeyboardActions(
                            onDone = {
                                if (password.isNotEmpty() && !isLockedOut && !uiState.isUnlockInProgress) {
                                    val submitted = password
                                    password = ""
                                    onUnlockWithPassword(submitted)
                                }
                            }
                        ),
                        trailingIcon = {
                            IconButton(
                                onClick = { showPassword = !showPassword },
                                modifier = Modifier.semantics {
                                    contentDescription = if (showPassword) {
                                        "Password visible. Tap to hide."
                                    } else {
                                        "Password hidden. Tap to reveal."
                                    }
                                }
                            ) {
                                Icon(
                                    imageVector = if (showPassword) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                    contentDescription = null
                                )
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("unlock_password_input")
                    )

                    if (uiState.unlockErrorMessage != null) {
                        Surface(
                            color = MaterialTheme.colorScheme.errorContainer,
                            shape = MaterialTheme.shapes.small,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Text(
                                    text = uiState.unlockErrorMessage,
                                    color = MaterialTheme.colorScheme.onErrorContainer,
                                    style = MaterialTheme.typography.bodySmall
                                )
                                if (isLockedOut) {
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        text = "Retry available in ${(uiState.unlockBackoffRemainingMs / 1000L) + 1L}s...",
                                        color = MaterialTheme.colorScheme.onErrorContainer,
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = JetBrainsMonoFontFamily
                                    )
                                }
                            }
                        }
                    }

                    Button(
                        onClick = {
                            val submitted = password
                            password = ""
                            onUnlockWithPassword(submitted)
                        },
                        enabled = password.isNotEmpty() && !uiState.isUnlockInProgress && !isLockedOut,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(52.dp)
                            .testTag("unlock_submit_button")
                    ) {
                        if (uiState.isUnlockInProgress) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(20.dp),
                                color = MaterialTheme.colorScheme.onPrimary,
                                strokeWidth = 2.dp
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            Text("Verifying Argon2id Key Envelope...")
                        } else {
                            Icon(imageVector = Icons.Filled.Lock, contentDescription = null)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Unlock Vault")
                        }
                    }

                    if (uiState.isBiometricEnrolledForRealVault) {
                        OutlinedButton(
                            onClick = onTriggerBiometricUnlock,
                            enabled = !uiState.isUnlockInProgress && !isLockedOut,
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(48.dp)
                                .testTag("unlock_biometric_button")
                        ) {
                            Icon(imageVector = Icons.Filled.Fingerprint, contentDescription = null)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Unlock with Hardware Biometrics")
                        }
                    }
                }
            }

            Text(
                text = "Forgot Master Password? An existing encrypted vault cannot be reset online. If you exported a .pvault backup file, you can restore it into a freshly initialized vault using its backup password.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
