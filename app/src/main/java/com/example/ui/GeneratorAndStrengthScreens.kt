package com.example.ui

import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoFixHigh
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Slider
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
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.example.security.OfflinePasswordStrengthEstimator
import com.example.security.PasswordGeneratorEngine
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.theme.StatusFair
import com.example.ui.theme.StatusStrong
import com.example.ui.theme.StatusVeryStrong
import com.example.ui.theme.StatusVeryWeak
import com.example.ui.theme.StatusWeak
import kotlin.math.roundToInt

@Composable
fun GeneratorTabScreen(
    uiState: VaultUiState,
    viewModel: VaultViewModel
) {
    var showGeneratedValue by remember { mutableStateOf(true) }
    val config = uiState.generatorConfig
    val result = uiState.generatedPasswordResult

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "Cryptographic Password Generator",
            style = MaterialTheme.typography.headlineMedium
        )
        Text(
            text = "Generates unbiased random passwords using Android OS SecureRandom and Fisher-Yates shuffling. Values are never automatically saved or written to history.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        // Output Card
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                when (result) {
                    is PasswordGeneratorEngine.GenerationResult.Success -> {
                        Surface(
                            color = MaterialTheme.colorScheme.surfaceVariant,
                            shape = MaterialTheme.shapes.medium,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 14.dp, vertical = 12.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(
                                    text = if (showGeneratedValue) result.password else "•".repeat(result.password.length),
                                    style = MaterialTheme.typography.titleMedium,
                                    fontFamily = JetBrainsMonoFontFamily,
                                    color = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier
                                        .weight(1f)
                                        .semantics {
                                            contentDescription = if (showGeneratedValue) {
                                                "Generated password visible"
                                            } else {
                                                "Generated password masked"
                                            }
                                        }
                                        .testTag("generator_output_text")
                                )

                                IconButton(
                                    onClick = { showGeneratedValue = !showGeneratedValue },
                                    modifier = Modifier.testTag("generator_toggle_visibility_button")
                                ) {
                                    Icon(
                                        imageVector = if (showGeneratedValue) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                        contentDescription = if (showGeneratedValue) "Mask generated password" else "Reveal generated password"
                                    )
                                }

                                IconButton(
                                    onClick = viewModel::regeneratePassword,
                                    modifier = Modifier.testTag("generator_regenerate_button")
                                ) {
                                    Icon(
                                        imageVector = Icons.Filled.Refresh,
                                        contentDescription = "Regenerate password"
                                    )
                                }
                            }
                        }

                        Text(
                            text = "${result.configExplanation} • Entropy: ~${result.estimatedEntropyBits.roundToInt()} bits",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = JetBrainsMonoFontFamily,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            OutlinedButton(
                                onClick = {
                                    viewModel.copySecretToClipboard("Generated Password", result.password)
                                },
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("generator_copy_button")
                            ) {
                                Icon(imageVector = Icons.Filled.ContentCopy, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Copy Secret")
                            }

                            Button(
                                onClick = {
                                    viewModel.sendGeneratedPasswordToNewCredential(result.password)
                                },
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("generator_save_to_passwords_button")
                            ) {
                                Icon(imageVector = Icons.Filled.Save, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Save to Passwords")
                            }
                        }
                    }

                    is PasswordGeneratorEngine.GenerationResult.InvalidConfig -> {
                        Surface(
                            color = MaterialTheme.colorScheme.errorContainer,
                            shape = MaterialTheme.shapes.small,
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("generator_error_banner")
                        ) {
                            Row(
                                modifier = Modifier.padding(12.dp),
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.ErrorOutline,
                                    contentDescription = "Invalid generator settings",
                                    tint = MaterialTheme.colorScheme.onErrorContainer
                                )
                                Text(
                                    text = result.reason,
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onErrorContainer
                                )
                            }
                        }
                    }
                }
            }
        }

        // Controls Card
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            modifier = Modifier.fillMaxWidth()
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
                    Text(
                        text = "Password Length",
                        style = MaterialTheme.typography.titleMedium
                    )
                    Text(
                        text = "${config.length} chars",
                        style = MaterialTheme.typography.titleMedium,
                        fontFamily = JetBrainsMonoFontFamily,
                        color = MaterialTheme.colorScheme.primary
                    )
                }

                Slider(
                    value = config.length.toFloat(),
                    onValueChange = { newLen ->
                        viewModel.updateGeneratorConfig(
                            config.copy(length = newLen.roundToInt().coerceIn(8, 64))
                        )
                    },
                    valueRange = 8f..64f,
                    steps = 55,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("generator_length_slider")
                )

                HorizontalDivider()

                GeneratorToggleRow(
                    title = "Uppercase Letters (A–Z)",
                    checked = config.includeUppercase,
                    tag = "generator_uppercase_switch",
                    onCheckedChange = {
                        viewModel.updateGeneratorConfig(config.copy(includeUppercase = it))
                    }
                )

                GeneratorToggleRow(
                    title = "Lowercase Letters (a–z)",
                    checked = config.includeLowercase,
                    tag = "generator_lowercase_switch",
                    onCheckedChange = {
                        viewModel.updateGeneratorConfig(config.copy(includeLowercase = it))
                    }
                )

                GeneratorToggleRow(
                    title = "Digits (0–9)",
                    checked = config.includeDigits,
                    tag = "generator_digits_switch",
                    onCheckedChange = {
                        viewModel.updateGeneratorConfig(config.copy(includeDigits = it))
                    }
                )

                GeneratorToggleRow(
                    title = "Symbols (!@#\$%^&*...)",
                    checked = config.includeSymbols,
                    tag = "generator_symbols_switch",
                    onCheckedChange = {
                        viewModel.updateGeneratorConfig(config.copy(includeSymbols = it))
                    }
                )

                HorizontalDivider()

                GeneratorToggleRow(
                    title = "Exclude Visually Ambiguous Characters (0, O, 1, l, I, |)",
                    checked = config.excludeAmbiguous,
                    tag = "generator_ambiguous_switch",
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
    title: String,
    checked: Boolean,
    tag: String,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.weight(1f)
        )
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            modifier = Modifier.testTag(tag)
        )
    }
}

@Composable
fun StrengthCheckTabScreen(
    uiState: VaultUiState,
    viewModel: VaultViewModel
) {
    var showInput by remember { mutableStateOf(false) }
    val candidate = uiState.strengthCheckerInput
    val report = remember(candidate, uiState.credentials) {
        viewModel.evaluatePasswordStrengthInActiveVault(candidate)
    }

    val ratingColor = when (report.rating) {
        OfflinePasswordStrengthEstimator.StrengthRating.VERY_WEAK -> StatusVeryWeak
        OfflinePasswordStrengthEstimator.StrengthRating.WEAK -> StatusWeak
        OfflinePasswordStrengthEstimator.StrengthRating.FAIR -> StatusFair
        OfflinePasswordStrengthEstimator.StrengthRating.STRONG -> StatusStrong
        OfflinePasswordStrengthEstimator.StrengthRating.VERY_STRONG -> StatusVeryStrong
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "Offline Password Strength Checker",
            style = MaterialTheme.typography.headlineMedium
        )
        Text(
            text = "Inspect any password locally in Airplane Mode. Checks dictionary roots, l33t substitutions, keyboard walks, sequential runs, dates, and reuse across your currently unlocked vault.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                OutlinedTextField(
                    value = candidate,
                    onValueChange = viewModel::updateStrengthCheckerInput,
                    label = { Text("Type or paste password to inspect offline") },
                    singleLine = true,
                    visualTransformation = if (showInput) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(
                        capitalization = KeyboardCapitalization.None,
                        autoCorrectEnabled = false,
                        keyboardType = KeyboardType.Password
                    ),
                    trailingIcon = {
                        IconButton(
                            onClick = { showInput = !showInput },
                            modifier = Modifier.semantics {
                                contentDescription = if (showInput) {
                                    "Checked password visible. Tap to mask."
                                } else {
                                    "Checked password masked. Tap to reveal."
                                }
                            }
                        ) {
                            Icon(
                                imageVector = if (showInput) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                contentDescription = null
                            )
                        }
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("strength_checker_input")
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Security,
                            contentDescription = null,
                            tint = ratingColor
                        )
                        Text(
                            text = "Rating: ${report.rating.label}",
                            style = MaterialTheme.typography.titleMedium,
                            color = ratingColor,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.testTag("strength_checker_rating_text")
                        )
                    }
                    Text(
                        text = "${report.scoreOutOf100}/100 (~${report.effectiveEntropyBits.roundToInt()} bits)",
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = JetBrainsMonoFontFamily
                    )
                }

                LinearProgressIndicator(
                    progress = { (report.scoreOutOf100 / 100f).coerceIn(0.04f, 1f) },
                    color = ratingColor,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(8.dp)
                )

                HorizontalDivider()

                Text(
                    text = "Detected Characteristics & Weaknesses",
                    style = MaterialTheme.typography.titleSmall
                )
                report.detectedWeaknesses.forEach { item ->
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.Top
                    ) {
                        Icon(
                            imageVector = if (report.rating == OfflinePasswordStrengthEstimator.StrengthRating.STRONG ||
                                report.rating == OfflinePasswordStrengthEstimator.StrengthRating.VERY_STRONG
                            ) Icons.Filled.CheckCircle else Icons.Filled.Warning,
                            contentDescription = null,
                            tint = ratingColor,
                            modifier = Modifier.size(18.dp)
                        )
                        Text(
                            text = item,
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                }

                HorizontalDivider()

                Text(
                    text = "Offline Improvement Suggestions",
                    style = MaterialTheme.typography.titleSmall
                )
                report.suggestions.forEach { tip ->
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.Top
                    ) {
                        Icon(
                            imageVector = Icons.Filled.AutoFixHigh,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(18.dp)
                        )
                        Text(
                            text = tip,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                if (candidate.isNotEmpty()) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        OutlinedButton(
                            onClick = { viewModel.updateStrengthCheckerInput("") },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Clear Input")
                        }
                        Button(
                            onClick = {
                                viewModel.sendGeneratedPasswordToNewCredential(candidate)
                                viewModel.updateStrengthCheckerInput("")
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Save to Passwords")
                        }
                    }
                }
            }
        }

        // Honest Offline Limitation Disclosure (Section 10)
        Surface(
            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.65f),
            shape = MaterialTheme.shapes.small,
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier.padding(12.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(
                    imageVector = Icons.Outlined.Info,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp)
                )
                Text(
                    text = "${report.offlineDisclaimer} Never saves checked inputs or history; input is cleared automatically when the vault locks.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}
