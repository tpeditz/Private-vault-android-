package com.example.security

import kotlin.math.log2
import kotlin.math.roundToInt

/**
 * 100% offline password strength analyzer and password/passphrase generator.
 * Makes zero network calls and never transmits passwords to external APIs.
 */
object OfflinePasswordStrengthEstimator {

    enum class StrengthBand(val label: String, val scoreFloor: Int) {
        CRITICAL("Critical", 0),
        WEAK("Weak", 25),
        FAIR("Fair", 50),
        STRONG("Strong", 75),
        FORTRESS("Fortress", 90)
    }

    data class StrengthReport(
        val score: Int, // 0..100
        val band: StrengthBand,
        val estimatedEntropyBits: Int,
        val length: Int,
        val hasUppercase: Boolean,
        val hasLowercase: Boolean,
        val hasDigits: Boolean,
        val hasSymbols: Boolean,
        val warnings: List<String>,
        val suggestions: List<String>,
        val isReusedInVault: Boolean = false
    )

    data class GeneratorConfig(
        val length: Int = 20,
        val includeUppercase: Boolean = true,
        val includeLowercase: Boolean = true,
        val includeDigits: Boolean = true,
        val includeSymbols: Boolean = true,
        val excludeAmbiguous: Boolean = true
    )

    private const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val LOWER = "abcdefghijklmnopqrstuvwxyz"
    private const val DIGITS = "0123456789"
    private const val SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?"
    private const val AMBIGUOUS = "Il1O0|"

    // Curated offline dictionary of common weak passwords, keyboard walks, and frequent stems (R19: fixed "maverick")
    private val COMMON_PASSWORDS_AND_STEMS = setOf(
        "password", "123456", "12345678", "123456789", "qwerty", "qwertyuiop",
        "asdfgh", "zxcvbn", "letmein", "welcome", "admin", "iloveyou", "monkey",
        "dragon", "baseball", "football", "shadow", "master", "sunshine", "superman",
        "trustno1", "passw0rd", "secret", "private", "vault", "india", "mumbai",
        "delhi", "krishna", "shiva", "ganesh", "google", "android", "samsung",
        "batman", "charlie", "donald", "mustang", "access", "freedom", "whatever",
        "abc123", "111111", "000000", "654321", "987654321", "maverick", "loveyou"
    )

    private val KEYBOARD_ROWS = listOf(
        "1234567890",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm"
    )

    private val EFF_PASSPHRASE_WORDS = listOf(
        "amber", "anchor", "apollo", "arctic", "arrow", "atlas", "aurora", "avalon",
        "bamboo", "barium", "beacon", "binary", "bison", "blizzard", "bonsai", "breeze",
        "canyon", "carbon", "cascade", "cedar", "celestial", "chisel", "cipher", "citadel",
        "cobalt", "comet", "compass", "condor", "coral", "cosmos", "crimson", "crystal",
        "cyclone", "dagger", "delta", "desert", "diamond", "dolphin", "dynamo", "eclipse",
        "emerald", "ember", "enigma", "equinox", "estuary", "everest", "falcon", "fjord",
        "flint", "forest", "fortress", "fossil", "fusion", "galaxy", "garnet", "gazelle",
        "geyser", "glacier", "granite", "gravity", "griffin", "harbor", "harvest", "helios",
        "horizon", "hunter", "iceberg", "indigo", "infinity", "ion", "island", "ivory",
        "jasper", "javelin", "juniper", "karma", "kestrel", "krypton", "lagoon", "lantern",
        "LAUREL".lowercase(), "legacy", "legend", "leopard", "liberty", "lightning", "lotus", "lunar",
        "magnet", "mammoth", "mantis", "marble", "matrix", "meadow", "mercury", "meteor",
        "mirage", "monarch", "monolith", "monsoon", "mosaic", "nebula", "nectar", "neptune",
        "nexus", "nimbus", "nomad", "nova", "obsidian", "odyssey", "omega", "onyx",
        "opal", "orbit", "orchid", "orion", "osprey", "oxygen", "paladin", "panther",
        "paradox", "pegasus", "pendulum", "phoenix", "pioneer", "planet", "platinum", "polaris",
        "prism", "pulsar", "pyramid", "quantum", "quartz", "quasar", "quiver", "radon",
        "raptor", "avenue", "redwood", "relic", "ridge", "ripple", "river", "ruby",
        "saffron", "sahara", "sapphire", "saturn", "savanna", "scarlet", "scepter", "sequoia",
        "serenity", "shadow", "sierra", "silicon", "silver", "solstice", "sonnet", "spark",
        "spectrum", "sphinx", "spiral", "spruce", "starlight", "stellar", "stratus", "summit",
        "sundial", "supernova", "tempest", "terra", "thistle", "thunder", "titanium", "topaz",
        "torrent", "trident", "tundra", "twilight", "typhoon", "umbra", "utopia", "valkyrie",
        "valley", "vanguard", "velvet", "venture", "verdict", "vertex", "VORTEX".lowercase(), "voyager",
        "warden", "whisper", "wildfire", "willow", "winter", "xenon", "yarrow", "zenith", "zephyr", "zircon"
    )

    fun evaluate(
        password: String,
        existingVaultPasswords: Collection<String> = emptyList()
    ): StrengthReport {
        if (password.isEmpty()) {
            return StrengthReport(
                score = 0,
                band = StrengthBand.CRITICAL,
                estimatedEntropyBits = 0,
                length = 0,
                hasUppercase = false,
                hasLowercase = false,
                hasDigits = false,
                hasSymbols = false,
                warnings = listOf("Password is empty."),
                suggestions = listOf("Use at least 14 characters or a 4-word passphrase."),
                isReusedInVault = false
            )
        }

        val length = password.length
        val hasUpper = password.any { it.isUpperCase() }
        val hasLower = password.any { it.isLowerCase() }
        val hasDigit = password.any { it.isDigit() }
        val hasSymbol = password.any { !it.isLetterOrDigit() }

        var poolSize = 0
        if (hasUpper) poolSize += 26
        if (hasLower) poolSize += 26
        if (hasDigit) poolSize += 10
        if (hasSymbol) poolSize += 32
        if (poolSize == 0) poolSize = 26

        // PV-SEC-003 / PV-QUALITY-001: Detect multi-word passphrases from the curated word list
        // so word-based passphrases report realistic word-list entropy (~7.66 bits/word) rather
        // than inflated character-pool entropy (length * log2(94)).
        val tokens = password.split('-', '_', ' ', '.').filter { it.isNotEmpty() }
        val wordTokens = tokens.filter { it.all { ch -> ch.isLetter() } }
        val knownWordMatches = wordTokens.count { it.lowercase() in EFF_PASSPHRASE_WORDS }
        val isWordlistPassphrase = wordTokens.size >= 3 && knownWordMatches >= (wordTokens.size + 1) / 2

        val rawEntropy = if (isWordlistPassphrase) {
            val bitsPerWord = log2(EFF_PASSPHRASE_WORDS.size.toDouble())
            val numericTokens = tokens.filter { it.all { ch -> ch.isDigit() } }
            val numberBits = numericTokens.sumOf { it.length * log2(10.0) }
            (wordTokens.size * bitsPerWord + numberBits).roundToInt()
        } else {
            (length * log2(poolSize.toDouble())).roundToInt()
        }

        val warnings = mutableListOf<String>()
        val suggestions = mutableListOf<String>()
        var penaltyBits = 0

        val normalized = password.lowercase()
        val leetNormalized = normalized
            .replace('0', 'o')
            .replace('1', 'i')
            .replace('3', 'e')
            .replace('4', 'a')
            .replace('5', 's')
            .replace('7', 't')
            .replace('@', 'a')
            .replace('$', 's')

        // 1. Check exact common password or embedded dictionary stems across ALL matches (R19)
        if (normalized in COMMON_PASSWORDS_AND_STEMS || leetNormalized in COMMON_PASSWORDS_AND_STEMS) {
            penaltyBits += 45
            warnings.add("Matches a very common dictionary password or l33t substitution.")
        } else {
            val matchedStems = COMMON_PASSWORDS_AND_STEMS.filter { stem ->
                stem.length >= 5 && (normalized.contains(stem) || leetNormalized.contains(stem))
            }
            if (matchedStems.isNotEmpty()) {
                // Accumulate penalty across all distinct dictionary stems present
                penaltyBits += (18 + (matchedStems.size - 1) * 12).coerceAtMost(48)
                val preview = matchedStems.take(3).joinToString(", ") { "\"$it\"" }
                warnings.add("Contains common dictionary stem(s) ($preview).")
            }
        }

        // 2. Check repeated character runs (e.g. "aaaa", "1111")
        if (hasRepeatedRun(password, minRun = 3)) {
            penaltyBits += 16
            warnings.add("Contains repeated character sequences (e.g., 'aaa' or '111').")
        }

        // 3. Check sequential ascending/descending characters (e.g. "abcd", "1234")
        if (hasSequentialRun(normalized, minRun = 4)) {
            penaltyBits += 18
            warnings.add("Contains sequential characters (e.g., 'abcd' or '1234').")
        }

        // 4. Check keyboard walks (e.g. "qwerty", "asdf")
        if (hasKeyboardWalk(normalized, minRun = 4)) {
            penaltyBits += 18
            warnings.add("Contains adjacent keyboard row patterns (e.g., 'qwerty' or 'asdf').")
        }

        // 5. Check date / year patterns (19xx or 20xx)
        if (Regex("(19[5-9]\\d|20[0-3]\\d)").containsMatchIn(password)) {
            penaltyBits += 10
            warnings.add("Contains a recognizable calendar year pattern.")
        }

        // 6. Check low unique character ratio (excluding multi-word passphrases which naturally repeat vowels/hyphens)
        val uniqueCount = password.toSet().size
        val uniqueRatio = uniqueCount.toDouble() / length.toDouble()
        if (!isWordlistPassphrase && length >= 8 && uniqueCount < 10 && uniqueRatio < 0.45) {
            penaltyBits += 15
            warnings.add("Low character variety ($uniqueCount unique characters).")
        }

        // 7. Check reuse inside active vault
        val isReused = existingVaultPasswords.any { it.isNotEmpty() && it == password }
        if (isReused) {
            penaltyBits += 25
            warnings.add("Reused password: this exact password is already used in your vault.")
            suggestions.add("Generate a unique password for every account.")
        }

        if (length < 12) {
            warnings.add("Short length ($length characters). Modern offline cracking requires 14+ characters.")
            suggestions.add("Increase length to at least 16 characters.")
        }

        val charClassesCount = listOf(hasUpper, hasLower, hasDigit, hasSymbol).count { it }
        if (charClassesCount < 3 && length < 18) {
            suggestions.add("Mix uppercase, lowercase, digits, and symbols—or use a 4+ word passphrase.")
        }

        val effectiveEntropy = (rawEntropy - penaltyBits).coerceAtLeast(0)
        val divisor = if (isWordlistPassphrase) 52.0 else 95.0
        val rawScore = ((effectiveEntropy.toDouble() / divisor) * 100.0).roundToInt()
        val cappedScore = when {
            length < 8 -> rawScore.coerceAtMost(24)
            normalized in COMMON_PASSWORDS_AND_STEMS -> rawScore.coerceAtMost(15)
            isReused -> rawScore.coerceAtMost(45)
            else -> rawScore
        }.coerceIn(0, 100)

        val band = when {
            cappedScore >= StrengthBand.FORTRESS.scoreFloor -> StrengthBand.FORTRESS
            cappedScore >= StrengthBand.STRONG.scoreFloor -> StrengthBand.STRONG
            cappedScore >= StrengthBand.FAIR.scoreFloor -> StrengthBand.FAIR
            cappedScore >= StrengthBand.WEAK.scoreFloor -> StrengthBand.WEAK
            else -> StrengthBand.CRITICAL
        }

        if (suggestions.isEmpty() && band != StrengthBand.FORTRESS) {
            suggestions.add("Add 4–6 more random characters or an extra passphrase word to increase strength.")
        }

        return StrengthReport(
            score = cappedScore,
            band = band,
            estimatedEntropyBits = effectiveEntropy,
            length = length,
            hasUppercase = hasUpper,
            hasLowercase = hasLower,
            hasDigits = hasDigit,
            hasSymbols = hasSymbol,
            warnings = warnings,
            suggestions = suggestions,
            isReusedInVault = isReused
        )
    }

    /**
     * Generates a cryptographically random password using unbiased rejection sampling via
     * `PasswordGeneratorEngine` (`PV-SEC-003`).
     */
    fun generatePassword(config: GeneratorConfig): String {
        val engineConfig = PasswordGeneratorEngine.GeneratorConfig(
            length = config.length.coerceIn(PasswordGeneratorEngine.MIN_LENGTH, PasswordGeneratorEngine.MAX_LENGTH),
            includeUppercase = config.includeUppercase,
            includeLowercase = config.includeLowercase,
            includeDigits = config.includeDigits,
            includeSymbols = config.includeSymbols,
            excludeAmbiguous = config.excludeAmbiguous
        )
        return when (val res = PasswordGeneratorEngine.generate(engineConfig)) {
            is PasswordGeneratorEngine.GenerationResult.Success -> res.password
            is PasswordGeneratorEngine.GenerationResult.InvalidConfig -> ""
        }
    }

    /**
     * Generates a multi-word passphrase from the curated offline wordlist using unbiased rejection
     * sampling (`PasswordGeneratorEngine.nextUnbiasedInt`, `PV-SEC-003`).
     */
    fun generatePassphrase(
        wordCount: Int = 5,
        separator: String = "-",
        capitalizeWords: Boolean = true,
        appendNumber: Boolean = true
    ): String {
        val count = wordCount.coerceIn(4, 8)
        val chosenWords = (0 until count).map {
            val wordIndex = PasswordGeneratorEngine.nextUnbiasedInt(EFF_PASSPHRASE_WORDS.size)
            val rawWord = EFF_PASSPHRASE_WORDS[wordIndex]
            if (capitalizeWords) {
                rawWord.replaceFirstChar { it.uppercaseChar() }
            } else {
                rawWord
            }
        }
        val base = chosenWords.joinToString(separator)
        return if (appendNumber) {
            val number = PasswordGeneratorEngine.nextUnbiasedInt(90) + 10
            "$base$separator$number"
        } else {
            base
        }
    }

    private fun hasRepeatedRun(input: String, minRun: Int): Boolean {
        if (input.length < minRun) return false
        var currentRun = 1
        for (i in 1 until input.length) {
            if (input[i] == input[i - 1]) {
                currentRun++
                if (currentRun >= minRun) return true
            } else {
                currentRun = 1
            }
        }
        return false
    }

    private fun hasSequentialRun(input: String, minRun: Int): Boolean {
        if (input.length < minRun) return false
        var ascRun = 1
        var descRun = 1
        for (i in 1 until input.length) {
            val diff = input[i].code - input[i - 1].code
            if (diff == 1) {
                ascRun++
                descRun = 1
            } else if (diff == -1) {
                descRun++
                ascRun = 1
            } else {
                ascRun = 1
                descRun = 1
            }
            if (ascRun >= minRun || descRun >= minRun) return true
        }
        return false
    }

    private fun hasKeyboardWalk(input: String, minRun: Int): Boolean {
        if (input.length < minRun) return false
        for (row in KEYBOARD_ROWS) {
            val reversed = row.reversed()
            for (start in 0..(row.length - minRun)) {
                val sub = row.substring(start, start + minRun)
                val revSub = reversed.substring(start, start + minRun)
                if (input.contains(sub) || input.contains(revSub)) {
                    return true
                }
            }
        }
        return false
    }
}
