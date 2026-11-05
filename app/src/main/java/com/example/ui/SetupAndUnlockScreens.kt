package com.example.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
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
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.example.security.OfflinePasswordStrengthEstimator

@Composable
fun SetupVaultScreen(
    isBusy: Boolean,
    onCreateVault: (
        realPassword: String,
        confirmRealPassword: String,
        enableDecoy: Boolean,
        decoyPassword: String,
        confirmDecoyPassword: String,
        seedStarterSamples: Boolean
    ) -> Unit
) {
    // R10 Fix: Use rememberSaveable for non-secret toggles and state so keyboard or orientation
    // changes during initial setup do not reset the setup screen layout.
    var realPassword by rememberSaveable { mutableStateOf("") }
    var confirmRealPassword by rememberSaveable { mutableStateOf("") }
    var showRealPassword by rememberSaveable { mutableStateOf(false) }

    var enableDecoy by rememberSaveable { mutableStateOf(false) }
    var decoyPassword by rememberSaveable { mutableStateOf("") }
    var confirmDecoyPassword by rememberSaveable { mutableStateOf("") }
    var showDecoyPassword by rememberSaveable { mutableStateOf(false) }

    var seedStarterSamples by rememberSaveable { mutableStateOf(true) }

    val strengthReport = remember(realPassword) {
        OfflinePasswordStrengthEstimator.evaluate(realPassword)
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .systemBarsPadding()
            .imePadding(),
        contentAlignment = Alignment.TopCenter
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .widthIn(max = 560.dp)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp, vertical = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Surface(
                shape = RoundedCornerShape(20.dp),
                color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.25f),
                modifier = Modifier.size(72.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        imageVector = Icons.Filled.Shield,
                        contentDescription = "Vault Shield",
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(40.dp)
                    )
                }
            }

            Text(
                text = "Initialize PRIVATE VAULT",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onBackground
            )

            Text(
                text = "100% Offline Encrypted Vault • Argon2id v1.3 + AES-256-GCM",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )

            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surface
                ),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = "Primary Vault Master Password",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Text(
                        text = "Your Master Password derives a 256-bit key using Argon2id. Because PRIVATE VAULT operates offline with zero cloud accounts, a forgotten Master Password cannot be recovered.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    OutlinedTextField(
                        value = realPassword,
                        onValueChange = { realPassword = it },
                        label = { Text("Master Password (min 8 chars)") },
                        singleLine = true,
                        visualTransformation = if (showRealPassword) {
                            VisualTransformation.None
                        } else {
                            PasswordVisualTransformation()
                        },
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password,
                            imeAction = ImeAction.Next
                        ),
                        trailingIcon = {
                            IconButton(onClick = { showRealPassword = !showRealPassword }) {
                                Icon(
                                    imageVector = if (showRealPassword) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                    contentDescription = if (showRealPassword) "Hide password" else "Show password"
                                )
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("setup_real_password_input")
                    )

                    if (realPassword.isNotEmpty()) {
                        PasswordStrengthInlineBar(report = strengthReport)
                    }

                    OutlinedTextField(
                        value = confirmRealPassword,
                        onValueChange = { confirmRealPassword = it },
                        label = { Text("Confirm Master Password") },
                        singleLine = true,
                        visualTransformation = if (showRealPassword) {
                            VisualTransformation.None
                        } else {
                            PasswordVisualTransformation()
                        },
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password,
                            imeAction = ImeAction.Done
                        ),
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("setup_confirm_real_password_input")
                    )
                }
            }

            // Optional Plausible Deniability Decoy Vault Card
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surface
                ),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Configure Decoy Vault (Optional)",
                                style = MaterialTheme.typography.titleMedium
                            )
                            Text(
                                text = "Creates an independent second vault unlocked by a distinct Decoy Password.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Switch(
                            checked = enableDecoy,
                            onCheckedChange = { enableDecoy = it },
                            modifier = Modifier.testTag("setup_enable_decoy_switch")
                        )
                    }

                    AnimatedVisibility(visible = enableDecoy) {
                        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            HorizontalDivider()
                            Text(
                                text = "Both Slot 0 (Real) and Slot 1 (Decoy) key envelopes always exist on disk and are evaluated on every unlock. Note: Biometric quick-unlock is automatically disabled while Decoy Mode is active.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )

                            OutlinedTextField(
                                value = decoyPassword,
                                onValueChange = { decoyPassword = it },
                                label = { Text("Decoy Vault Password (min 8 chars)") },
                                singleLine = true,
                                visualTransformation = if (showDecoyPassword) {
                                    VisualTransformation.None
                                } else {
                                    PasswordVisualTransformation()
                                },
                                keyboardOptions = KeyboardOptions(
                                    keyboardType = KeyboardType.Password,
                                    imeAction = ImeAction.Next
                                ),
                                trailingIcon = {
                                    IconButton(onClick = { showDecoyPassword = !showDecoyPassword }) {
                                        Icon(
                                            imageVector = if (showDecoyPassword) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                            contentDescription = if (showDecoyPassword) "Hide decoy password" else "Show decoy password"
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
                                visualTransformation = if (showDecoyPassword) {
                                    VisualTransformation.None
                                } else {
                                    PasswordVisualTransformation()
                                },
                                keyboardOptions = KeyboardOptions(
                                    keyboardType = KeyboardType.Password,
                                    imeAction = ImeAction.Done
                                ),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .testTag("setup_confirm_decoy_password_input")
                            )
                        }
                    }
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Checkbox(
                    checked = seedStarterSamples,
                    onCheckedChange = { seedStarterSamples = it },
                    modifier = Modifier.testTag("setup_seed_samples_checkbox")
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Include encrypted starter notes & plausible decoy items",
                    style = MaterialTheme.typography.bodyMedium
                )
            }

            Button(
                onClick = {
                    onCreateVault(
                        realPassword,
                        confirmRealPassword,
                        enableDecoy,
                        decoyPassword,
                        confirmDecoyPassword,
                        seedStarterSamples
                    )
                },
                enabled = !isBusy && realPassword.length >= 8 && confirmRealPassword.length >= 8,
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(54.dp)
                    .testTag("setup_create_vault_button")
            ) {
                if (isBusy) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(22.dp),
                        strokeWidth = 2.5.dp,
                        color = MaterialTheme.colorScheme.onPrimary
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Text("Deriving Argon2id Vault Keys…")
                } else {
                    Icon(Icons.Filled.Lock, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Create Encrypted Vault", fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}

@Composable
fun UnlockVaultScreen(
    isBusy: Boolean,
    isBiometricAvailable: Boolean,
    failedAttempts: Int,
    cooldownRemainingMs: Long,
    lastKdfDurationMs: Long,
    onUnlockWithPassword: (String) -> Unit,
    onRequestBiometricUnlock: () -> Unit
) {
    var password by rememberSaveable { mutableStateOf("") }
    var showPassword by rememberSaveable { mutableStateOf(false) }

    // U03 Fix: Full-bleed background + single systemBarsPadding + imePadding + verticalScroll
    // so opening the keyboard smoothly scrolls the unlock card without black or blank regions.
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .systemBarsPadding()
            .imePadding(),
        contentAlignment = Alignment.Center
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .widthIn(max = 480.dp)
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(18.dp)
        ) {
            Surface(
                shape = RoundedCornerShape(22.dp),
                color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.25f),
                modifier = Modifier.size(80.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        imageVector = Icons.Filled.Shield,
                        contentDescription = "PRIVATE VAULT Emblem",
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(44.dp)
                    )
                }
            }

            Text(
                text = "PRIVATE VAULT",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onBackground
            )

            Text(
                text = "Enter your Vault Password to unwrap your AES-256-GCM key envelope",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )

            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surface
                ),
                shape = RoundedCornerShape(18.dp)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    OutlinedTextField(
                        value = password,
                        onValueChange = { password = it },
                        label = { Text("Vault Password") },
                        singleLine = true,
                        enabled = !isBusy,
                        visualTransformation = if (showPassword) {
                            VisualTransformation.None
                        } else {
                            PasswordVisualTransformation()
                        },
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password,
                            imeAction = ImeAction.Done
                        ),
                        keyboardActions = KeyboardActions(
                            onDone = {
                                if (password.isNotBlank() && !isBusy) {
                                    val submitted = password
                                    password = ""
                                    onUnlockWithPassword(submitted)
                                }
                            }
                        ),
                        trailingIcon = {
                            IconButton(onClick = { showPassword = !showPassword }) {
                                Icon(
                                    imageVector = if (showPassword) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                    contentDescription = if (showPassword) "Hide password" else "Show password"
                                )
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("unlock_password_input")
                    )

                    Button(
                        onClick = {
                            val submitted = password
                            password = ""
                            onUnlockWithPassword(submitted)
                        },
                        enabled = !isBusy && password.isNotBlank(),
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(52.dp)
                            .testTag("unlock_submit_button")
                    ) {
                        if (isBusy) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(20.dp),
                                strokeWidth = 2.5.dp,
                                color = MaterialTheme.colorScheme.onPrimary
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            Text("Verifying Argon2id Envelopes…")
                        } else {
                            Icon(Icons.Filled.Lock, contentDescription = null)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Unlock Vault", fontWeight = FontWeight.Bold)
                        }
                    }

                    if (isBiometricAvailable) {
                        OutlinedButton(
                            onClick = onRequestBiometricUnlock,
                            enabled = !isBusy,
                            shape = RoundedCornerShape(14.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(50.dp)
                                .testTag("unlock_biometric_button")
                        ) {
                            Icon(Icons.Filled.Fingerprint, contentDescription = null)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Biometric Quick-Unlock")
                        }
                    }

                    if (failedAttempts > 0 || lastKdfDurationMs > 0L) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            if (failedAttempts > 0) {
                                Text(
                                    text = "Failed attempts: $failedAttempts",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.error
                                )
                            }
                            if (lastKdfDurationMs > 0L) {
                                Text(
                                    text = "2-Slot KDF: ${lastKdfDurationMs}ms",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }

            Text(
                text = "Zero Cloud Sync • Zero Analytics • Local Argon2id + AES-256-GCM",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )
        }
    }
}

@Composable
fun PasswordStrengthInlineBar(
    report: OfflinePasswordStrengthEstimator.StrengthReport
) {
    val barColor = when (report.band) {
        OfflinePasswordStrengthEstimator.StrengthBand.CRITICAL -> Color(0xFFEF4444)
        OfflinePasswordStrengthEstimator.StrengthBand.WEAK -> Color(0xFFF97316)
        OfflinePasswordStrengthEstimator.StrengthBand.FAIR -> Color(0xFFF59E0B)
        OfflinePasswordStrengthEstimator.StrengthBand.STRONG -> Color(0xFF10B981)
        OfflinePasswordStrengthEstimator.StrengthBand.FORTRESS -> Color(0xFF38BDF8)
    }

    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = "Strength: ${report.band.label} (${report.score}/100)",
                style = MaterialTheme.typography.labelMedium,
                color = barColor,
                fontWeight = FontWeight.SemiBold
            )
            Text(
                text = "~${report.estimatedEntropyBits} bits entropy",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        LinearProgressIndicator(
            progress = { (report.score / 100f).coerceIn(0.05f, 1f) },
            color = barColor,
            trackColor = MaterialTheme.colorScheme.surfaceVariant,
            modifier = Modifier
                .fillMaxWidth()
                .height(6.dp)
        )
    }
}
