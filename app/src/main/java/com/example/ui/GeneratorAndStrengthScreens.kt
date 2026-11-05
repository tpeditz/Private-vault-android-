package com.example.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Slider
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.security.OfflinePasswordStrengthEstimator

@Composable
fun GeneratorAndStrengthScreen(
    uiState: VaultUiState,
    viewModel: VaultViewModel
) {
    val config = uiState.generatorConfig
    val candidate = uiState.generatedCandidate
    val existingPasswords = remember(uiState.credentials) {
        uiState.credentials.map { it.password }
    }
    val report = remember(candidate, existingPasswords) {
        OfflinePasswordStrengthEstimator.evaluate(candidate, existingPasswords)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(
            text = "Cryptographic Password & Passphrase Generator",
            style = MaterialTheme.typography.headlineSmall
        )
        Text(
            text = "100% offline CSPRNG generation via SecureRandom. Never leaves your device.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        // Generated Candidate Display Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Surface(
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = candidate,
                        style = MaterialTheme.typography.titleMedium,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier
                            .padding(16.dp)
                            .testTag("generated_password_display")
                    )
                }

                PasswordStrengthInlineBar(report = report)

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Button(
                        onClick = {
                            viewModel.copySecretToClipboard("Generated Password", candidate)
                        },
                        modifier = Modifier
                            .weight(1f)
                            .testTag("generator_copy_button")
                    ) {
                        Icon(Icons.Filled.ContentCopy, contentDescription = null)
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Copy")
                    }

                    OutlinedButton(
                        onClick = viewModel::regeneratePasswordCandidate,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("generator_regenerate_button")
                    ) {
                        Icon(Icons.Filled.Refresh, contentDescription = null)
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Random Password")
                    }
                }

                OutlinedButton(
                    onClick = { viewModel.generatePassphraseCandidate(uiState.passphraseWordCount) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("generator_passphrase_button")
                ) {
                    Text("Generate ${uiState.passphraseWordCount}-Word High-Entropy Passphrase")
                }
            }
        }

        // Character Set Controls
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "Password Length",
                        style = MaterialTheme.typography.titleSmall
                    )
                    Text(
                        text = "${config.length} characters",
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.primary,
                        fontWeight = FontWeight.Bold
                    )
                }

                Slider(
                    value = config.length.toFloat(),
                    onValueChange = { newLen ->
                        viewModel.updateGeneratorConfig(config.copy(length = newLen.toInt()))
                    },
                    valueRange = 8f..64f,
                    steps = 55,
                    modifier = Modifier.testTag("generator_length_slider")
                )

                GeneratorToggleRow(
                    label = "Uppercase Letters (A–Z)",
                    checked = config.includeUppercase,
                    onCheckedChange = {
                        viewModel.updateGeneratorConfig(config.copy(includeUppercase = it))
                    }
                )
                GeneratorToggleRow(
                    label = "Lowercase Letters (a–z)",
                    checked = config.includeLowercase,
                    onCheckedChange = {
                        viewModel.updateGeneratorConfig(config.copy(includeLowercase = it))
                    }
                )
                GeneratorToggleRow(
                    label = "Digits (0–9)",
                    checked = config.includeDigits,
                    onCheckedChange = {
                        viewModel.updateGeneratorConfig(config.copy(includeDigits = it))
                    }
                )
                GeneratorToggleRow(
                    label = "Symbols (!@#$%^&*…)",
                    checked = config.includeSymbols,
                    onCheckedChange = {
                        viewModel.updateGeneratorConfig(config.copy(includeSymbols = it))
                    }
                )
                GeneratorToggleRow(
                    label = "Exclude Ambiguous Characters (I, l, 1, O, 0)",
                    checked = config.excludeAmbiguous,
                    onCheckedChange = {
                        viewModel.updateGeneratorConfig(config.copy(excludeAmbiguous = it))
                    }
                )
            }
        }
    }
}

@Composable
private fun GeneratorToggleRow(
    label: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.weight(1f)
        )
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange
        )
    }
}

@Composable
fun StrengthAuditTabScreen(
    uiState: VaultUiState,
    viewModel: VaultViewModel
) {
    val existingPasswords = remember(uiState.credentials) {
        uiState.credentials.map { it.password }
    }
    val interactiveReport = remember(uiState.strengthCheckerInput, existingPasswords) {
        OfflinePasswordStrengthEstimator.evaluate(uiState.strengthCheckerInput, existingPasswords)
    }

    // Vault-wide offline audit summary
    val auditSummary = remember(uiState.credentials) {
        val reports = uiState.credentials.map { cred ->
            val others = uiState.credentials.filter { it.id != cred.id }.map { it.password }
            cred to OfflinePasswordStrengthEstimator.evaluate(cred.password, others)
        }
        val weakCount = reports.count { it.second.score < 50 }
        val reusedCount = reports.count { it.second.isReusedInVault }
        val strongCount = reports.count { it.second.score >= 75 }
        Triple(weakCount, reusedCount, strongCount)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(
            text = "Offline Password Strength & Vault Audit",
            style = MaterialTheme.typography.headlineSmall
        )
        Text(
            text = "Evaluates entropy, keyboard walks, repeated sequences, common dictionary stems, and local reuse with zero network calls.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        // Vault Audit Summary Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = "Active Vault Credential Health (${uiState.credentials.size} total)",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.primary
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    AuditMetricPill(
                        label = "Strong / Fortress",
                        count = auditSummary.third,
                        color = MaterialTheme.colorScheme.secondary
                    )
                    AuditMetricPill(
                        label = "Weak (<50)",
                        count = auditSummary.first,
                        color = MaterialTheme.colorScheme.error
                    )
                    AuditMetricPill(
                        label = "Reused",
                        count = auditSummary.second,
                        color = MaterialTheme.colorScheme.tertiary
                    )
                }
            }
        }

        // Interactive Offline Strength Sandbox
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    text = "Test Any Password Offline",
                    style = MaterialTheme.typography.titleMedium
                )

                OutlinedTextField(
                    value = uiState.strengthCheckerInput,
                    onValueChange = viewModel::setStrengthCheckerInput,
                    label = { Text("Enter password to analyze") },
                    singleLine = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("strength_checker_input")
                )

                PasswordStrengthInlineBar(report = interactiveReport)

                HorizontalDivider()

                Text(
                    text = "Character Classes: " +
                        listOfNotNull(
                            if (interactiveReport.hasUppercase) "Upper" else null,
                            if (interactiveReport.hasLowercase) "Lower" else null,
                            if (interactiveReport.hasDigits) "Digits" else null,
                            if (interactiveReport.hasSymbols) "Symbols" else null
                        ).joinToString(", ").ifEmpty { "None" },
                    style = MaterialTheme.typography.bodySmall
                )

                if (interactiveReport.warnings.isNotEmpty()) {
                    Text(
                        text = "Detected Vulnerabilities:",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.error
                    )
                    interactiveReport.warnings.forEach { warn ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Icon(
                                Icons.Filled.Warning,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.error
                            )
                            Text(text = warn, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }

                if (interactiveReport.suggestions.isNotEmpty()) {
                    Text(
                        text = "Recommendations:",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.secondary
                    )
                    interactiveReport.suggestions.forEach { sug ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Icon(
                                Icons.Filled.CheckCircle,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.secondary
                            )
                            Text(text = sug, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun AuditMetricPill(
    label: String,
    count: Int,
    color: androidx.compose.ui.graphics.Color
) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = count.toString(),
            style = MaterialTheme.typography.headlineMedium,
            color = color,
            fontWeight = FontWeight.Bold
        )
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
