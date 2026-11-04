package com.example.security

import java.security.SecureRandom
import kotlin.math.ln

/**
 * Cryptographically secure Password Generator (Section 09).
 *
 * Security Rules:
 * - Uses java.security.SecureRandom exclusively.
 * - Unbiased rejection sampling (`nextUnbiasedInt`) for all pool and shuffle selections.
 * - Guarantees at least one character from each enabled character class, then executes a
 *   cryptographically secure Fisher-Yates shuffle so required characters are uniformly distributed
 *   across all positions (never putting uppercase always first or symbol always last).
 * - Rejects impossible combinations with explicit validation errors rather than silently weakening output.
 */
object PasswordGeneratorEngine {

    private const val UPPERCASE_ALL = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val LOWERCASE_ALL = "abcdefghijklmnopqrstuvwxyz"
    private const val DIGITS_ALL = "0123456789"
    private const val SYMBOLS_ALL = "!@#$%^&*()-_=+[]{}|;:,.<>?/~"

    private val AMBIGUOUS_CHARS = setOf('0', 'O', 'o', '1', 'l', 'I', '|')

    const val MIN_LENGTH = 8
    const val MAX_LENGTH = 64
    const val DEFAULT_LENGTH = 20

    private val secureRandom = SecureRandom()

    data class GeneratorConfig(
        val length: Int = DEFAULT_LENGTH,
        val includeUppercase: Boolean = true,
        val includeLowercase: Boolean = true,
        val includeDigits: Boolean = true,
        val includeSymbols: Boolean = true,
        val excludeAmbiguous: Boolean = true
    )

    sealed interface GenerationResult {
        data class Success(
            val password: String,
            val poolSize: Int,
            val estimatedEntropyBits: Double,
            val configExplanation: String
        ) : GenerationResult

        data class InvalidConfig(val reason: String) : GenerationResult
    }

    fun generate(config: GeneratorConfig): GenerationResult {
        if (config.length !in MIN_LENGTH..MAX_LENGTH) {
            return GenerationResult.InvalidConfig(
                "Password length must be between $MIN_LENGTH and $MAX_LENGTH characters."
            )
        }

        val activePools = mutableListOf<String>()
        val categoryNames = mutableListOf<String>()

        if (config.includeUppercase) {
            val pool = filterPool(UPPERCASE_ALL, config.excludeAmbiguous)
            activePools.add(pool)
            categoryNames.add("Uppercase")
        }
        if (config.includeLowercase) {
            val pool = filterPool(LOWERCASE_ALL, config.excludeAmbiguous)
            activePools.add(pool)
            categoryNames.add("Lowercase")
        }
        if (config.includeDigits) {
            val pool = filterPool(DIGITS_ALL, config.excludeAmbiguous)
            activePools.add(pool)
            categoryNames.add("Digits")
        }
        if (config.includeSymbols) {
            val pool = filterPool(SYMBOLS_ALL, config.excludeAmbiguous)
            activePools.add(pool)
            categoryNames.add("Symbols")
        }

        if (activePools.isEmpty()) {
            return GenerationResult.InvalidConfig(
                "Enable at least one character category (Uppercase, Lowercase, Digits, or Symbols)."
            )
        }

        if (config.length < activePools.size) {
            return GenerationResult.InvalidConfig(
                "Length (${config.length}) is shorter than the number of required categories (${activePools.size})."
            )
        }

        val combinedPool = activePools.joinToString("")
        if (combinedPool.isEmpty()) {
            return GenerationResult.InvalidConfig("Character pool is empty after filtering.")
        }

        val chars = CharArray(config.length)

        // 1. Pick one unbiased character from each enabled category
        for (i in activePools.indices) {
            val categoryPool = activePools[i]
            chars[i] = categoryPool[nextUnbiasedInt(categoryPool.length)]
        }

        // 2. Fill the remaining characters uniformly from the combined character pool
        for (i in activePools.size until config.length) {
            chars[i] = combinedPool[nextUnbiasedInt(combinedPool.length)]
        }

        // 3. Cryptographically secure unbiased Fisher-Yates shuffle across all positions
        for (i in chars.lastIndex downTo 1) {
            val j = nextUnbiasedInt(i + 1)
            val tmp = chars[i]
            chars[i] = chars[j]
            chars[j] = tmp
        }

        val password = String(chars)
        val entropyBits = config.length * (ln(combinedPool.length.toDouble()) / ln(2.0))
        val ambiguousNote = if (config.excludeAmbiguous) "excluding look-alike characters (0, O, 1, l, I)" else "including all characters"
        val explanation = "${config.length} characters using ${categoryNames.joinToString(", ")} ($ambiguousNote) • Pool: ${combinedPool.length} symbols."

        return GenerationResult.Success(
            password = password,
            poolSize = combinedPool.length,
            estimatedEntropyBits = entropyBits,
            configExplanation = explanation
        )
    }

    private fun filterPool(source: String, excludeAmbiguous: Boolean): String {
        if (!excludeAmbiguous) return source
        return source.filterNot { it in AMBIGUOUS_CHARS }
    }

    /**
     * Unbiased random integer in [0, bound) using rejection sampling over 31-bit values.
     */
    private fun nextUnbiasedInt(bound: Int): Int {
        require(bound > 0) { "Bound must be positive" }
        if ((bound and -bound) == bound) {
            // Power of 2
            return secureRandom.nextInt(bound)
        }
        var bits: Int
        var value: Int
        val maxMultiple = Int.MAX_VALUE - (Int.MAX_VALUE % bound)
        do {
            bits = secureRandom.nextInt() ushr 1
            value = bits % bound
        } while (bits >= maxMultiple)
        return value
    }
}
