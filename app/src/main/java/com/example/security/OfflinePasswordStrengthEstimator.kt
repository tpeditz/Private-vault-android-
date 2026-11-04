package com.example.security

import java.util.Locale
import kotlin.math.ln

/**
 * 100% Offline Password Strength & Pattern Estimator (Section 10).
 *
 * - Never transmits passwords, hashes, or prefixes over the network.
 * - Evaluates common passwords, dictionary words, l33t-speak substitutions, keyboard walks,
 *   sequential runs, character repetition, date/year patterns, length, and active-vault reuse.
 * - Never marks a short patterned password as Strong merely because it contains an uppercase,
 *   digit, and symbol (e.g. `Pass123!` or `Qwerty1!`).
 */
object OfflinePasswordStrengthEstimator {

    enum class StrengthRating(val label: String, val scoreFloor: Int) {
        VERY_WEAK("Very weak", 0),
        WEAK("Weak", 1),
        FAIR("Fair", 2),
        STRONG("Strong", 3),
        VERY_STRONG("Very strong", 4)
    }

    data class StrengthReport(
        val rating: StrengthRating,
        val scoreOutOf100: Int,
        val effectiveEntropyBits: Double,
        val detectedWeaknesses: List<String>,
        val suggestions: List<String>,
        val reusedServiceNames: List<String>,
        val offlineDisclaimer: String = "Offline estimate only: This analysis runs 100% locally on your device. Because PRIVATE VAULT never connects to online breach services, it cannot check if a password was leaked in an external website breach."
    )

    // Bundled high-risk common passwords, stems, and dictionary roots (permissively curated offline set)
    private val COMMON_PASSWORDS_AND_STEMS = setOf(
        "password", "passw0rd", "p@ssword", "p@ssw0rd", "qwerty", "qwertyuiop",
        "123456", "12345678", "123456789", "1234567890", "admin", "administrator",
        "welcome", "letmein", "monkey", "dragon", "baseball", "football", "superman",
        "batman", "trustno1", "iloveyou", "sunshine", "princess", "starwars", "master",
        "shadow", "ashley", "michael", "charlie", "andrew", "thomas", "robert", "daniel",
        "jessica", "jennifer", "computer", "internet", "secret", "private", "vault",
        "security", "freedom", "whatever", "nothing", "zaq12wsx", "1q2w3e4r", "1qaz2wsx",
        "abcd1234", "pakistan", "india", "london", "america", "chelsea", "arsenal",
        "liverpool", "barcelona", "real", "madrid", "loveyou", "forever", "summer",
        "winter", "autumn", "spring", "january", "february", "august", "october",
        "november", "december", "monday", "tuesday", "friday", "saturday", "sunday",
        "company", "service", "account", "banking", "wallet", "crypto", "bitcoin",
        "pokemon", "naruto", "matrix", "averick", "mustang", "ferrari", "corvette",
        "harley", "ranger", "hunter", "killer", "buster", "pepper", "ginger", "cookie",
        "peanut", "orange", "banana", "coffee", "cheese", "access", "system", "server"
    )

    private val KEYBOARD_ROWS = listOf(
        "1234567890-=",
        "qwertyuiop[]",
        "asdfghjkl;'",
        "zxcvbnm,./",
        "0987654321",
        "poiuytrewq",
        "lkjhgfdsa",
        "mnbvcxz"
    )

    private val LEET_MAP = mapOf(
        '@' to 'a',
        '4' to 'a',
        '3' to 'e',
        '1' to 'i',
        '!' to 'i',
        '0' to 'o',
        '$' to 's',
        '5' to 's',
        '7' to 't',
        '+' to 't'
    )

    /**
     * Evaluates a password completely offline.
     *
     * @param password The candidate password to inspect.
     * @param existingVaultCredentials Optional list of `(recordId, serviceName, password)` from the
     *        currently unlocked vault ONLY (never across vaults) to detect local password reuse.
     * @param excludeRecordId When editing an existing credential, its own recordId so it does not
     *        trigger a self-reuse warning.
     */
    fun evaluate(
        password: String,
        existingVaultCredentials: List<Triple<String, String, String>> = emptyList(),
        excludeRecordId: String? = null
    ): StrengthReport {
        if (password.isEmpty()) {
            return StrengthReport(
                rating = StrengthRating.VERY_WEAK,
                scoreOutOf100 = 0,
                effectiveEntropyBits = 0.0,
                detectedWeaknesses = listOf("Password is empty."),
                suggestions = listOf("Enter a password or use the Generator to create a 20+ character random password."),
                reusedServiceNames = emptyList()
            )
        }

        val weaknesses = mutableListOf<String>()
        val suggestions = mutableListOf<String>()
        val lower = password.lowercase(Locale.ROOT)
        val deLeeted = normalizeLeet(lower)
        val alphaOnly = deLeeted.filter { it in 'a'..'z' }

        // 1. Check active-vault password reuse
        val reusedServices = existingVaultCredentials
            .asSequence()
            .filter { (id, _, savedPassword) ->
                id != excludeRecordId && savedPassword.isNotEmpty() && savedPassword == password
            }
            .map { (_, service, _) -> service.ifBlank { "Unnamed Credential" } }
            .distinct()
            .toList()

        if (reusedServices.isNotEmpty()) {
            weaknesses.add("Reused across ${reusedServices.size} saved account(s) in this vault (${reusedServices.take(3).joinToString(", ")}).")
            suggestions.add("Generate a unique password for every account so one compromised service cannot unlock others.")
        }

        // 2. Character classes & base pool estimation
        val hasUpper = password.any { it.isUpperCase() }
        val hasLower = password.any { it.isLowerCase() }
        val hasDigit = password.any { it.isDigit() }
        val hasSymbol = password.any { !it.isLetterOrDigit() }

        var poolSize = 0
        if (hasLower) poolSize += 26
        if (hasUpper) poolSize += 26
        if (hasDigit) poolSize += 10
        if (hasSymbol) poolSize += 30

        val uniqueChars = password.toSet().size
        val uniquenessRatio = uniqueChars.toDouble() / password.length.toDouble()

        // Start with raw length * log2(pool), then penalize heavily for predictable patterns
        var effectiveBits = password.length * (ln(poolSize.coerceAtLeast(2).toDouble()) / ln(2.0))
        effectiveBits *= (0.45 + 0.55 * uniquenessRatio)

        // 3. Length checks
        when {
            password.length < 8 -> {
                weaknesses.add("Critically short (${password.length} characters); vulnerable to rapid brute-force guessing.")
                suggestions.add("Increase length to at least 16–20 characters.")
                effectiveBits = effectiveBits.coerceAtMost(22.0)
            }
            password.length < 12 -> {
                weaknesses.add("Short length (${password.length} characters); modern offline attacks test short combinations quickly.")
                suggestions.add("Use 16 to 20+ characters for strong long-term protection.")
            }
        }

        // 4. Exact or stem dictionary / common password detection (including l33t substitutions)
        val matchedStem = COMMON_PASSWORDS_AND_STEMS.firstOrNull { stem ->
            stem.length >= 5 && (lower.contains(stem) || deLeeted.contains(stem) || alphaOnly == stem)
        }
        if (matchedStem != null) {
            weaknesses.add("Contains a common dictionary word or password pattern (\"$matchedStem\"), even with symbol/number substitutions.")
            suggestions.add("Avoid common words with predictable numbers or symbols at the end (like Pass123!). Use random characters or 4+ unrelated words.")
            effectiveBits -= (matchedStem.length * 3.8)
            if (alphaOnly == matchedStem && password.length <= matchedStem.length + 4) {
                // Classic e.g. "Password1!" or "P@ssw0rd1"
                effectiveBits = effectiveBits.coerceAtMost(26.0)
            }
        }

        // 5. Keyboard walk detection
        if (hasKeyboardWalk(lower)) {
            weaknesses.add("Contains an adjacent keyboard pattern (such as qwerty, asdf, or 1234).")
            suggestions.add("Remove keyboard-row sequences that password crackers test first.")
            effectiveBits -= 18.0
        }

        // 6. Sequential alphabetical or numeric runs (e.g. abcd, 1234, 4321)
        if (hasSequentialRun(lower, minRun = 4)) {
            weaknesses.add("Contains a predictable sequential run of letters or numbers.")
            suggestions.add("Break up sequential runs like '1234' or 'abcd'.")
            effectiveBits -= 15.0
        }

        // 7. Repeated characters (e.g. aaaa, 1111, !!)
        if (hasRepeatedCharacters(password, minRepeat = 3)) {
            weaknesses.add("Contains repeated identical characters in a row.")
            suggestions.add("Replace repeated characters with random variety.")
            effectiveBits -= 12.0
        }

        // 8. Predictable years or dates (1970..2039 or MMDDYYYY)
        if (Regex("(19[5-9]\\d|20[0-3]\\d)").containsMatchIn(password)) {
            weaknesses.add("Contains a recognizable calendar year (1950–2039).")
            suggestions.add("Avoid birth years, anniversaries, or current years.")
            effectiveBits -= 10.0
        }

        // 9. Single character class check
        val classCount = listOf(hasUpper, hasLower, hasDigit, hasSymbol).count { it }
        if (classCount == 1 && password.length < 20) {
            weaknesses.add("Uses only one type of character.")
            suggestions.add("Mix uppercase, lowercase, digits, and symbols.")
            effectiveBits -= 10.0
        }

        // 10. Reuse penalty
        if (reusedServices.isNotEmpty()) {
            effectiveBits = effectiveBits.coerceAtMost(35.0)
        }

        effectiveBits = effectiveBits.coerceIn(0.0, 140.0)

        val rating = when {
            password.length < 8 || effectiveBits < 28.0 -> StrengthRating.VERY_WEAK
            password.length < 10 || effectiveBits < 45.0 -> StrengthRating.WEAK
            effectiveBits < 65.0 -> StrengthRating.FAIR
            effectiveBits < 88.0 -> StrengthRating.STRONG
            else -> StrengthRating.VERY_STRONG
        }

        val scoreOutOf100 = ((effectiveBits / 100.0) * 100.0).toInt().coerceIn(
            minimumValue = if (password.isNotEmpty()) 5 else 0,
            maximumValue = 100
        )

        if (weaknesses.isEmpty()) {
            weaknesses.add("No obvious offline dictionary words, keyboard walks, or vault reuse detected.")
        }
        if (suggestions.isEmpty()) {
            if (rating == StrengthRating.VERY_STRONG || rating == StrengthRating.STRONG) {
                suggestions.add("Keep this password unique to a single service and store it only in your encrypted vault.")
            } else {
                suggestions.add("Use the built-in Generator to create a 20-character random password.")
            }
        }

        return StrengthReport(
            rating = rating,
            scoreOutOf100 = scoreOutOf100,
            effectiveEntropyBits = effectiveBits,
            detectedWeaknesses = weaknesses,
            suggestions = suggestions,
            reusedServiceNames = reusedServices
        )
    }

    private fun normalizeLeet(input: String): String {
        val sb = StringBuilder(input.length)
        for (c in input) {
            sb.append(LEET_MAP[c] ?: c)
        }
        return sb.toString()
    }

    private fun hasKeyboardWalk(lower: String): Boolean {
        if (lower.length < 4) return false
        for (row in KEYBOARD_ROWS) {
            for (i in 0..(row.length - 4)) {
                val slice = row.substring(i, i + 4)
                if (lower.contains(slice)) return true
            }
        }
        return false
    }

    private fun hasSequentialRun(lower: String, minRun: Int): Boolean {
        if (lower.length < minRun) return false
        var ascRun = 1
        var descRun = 1
        for (i in 1 until lower.length) {
            val prev = lower[i - 1].code
            val curr = lower[i].code
            if (curr == prev + 1 && lower[i].isLetterOrDigit() && lower[i - 1].isLetterOrDigit()) {
                ascRun++
                if (ascRun >= minRun) return true
            } else {
                ascRun = 1
            }
            if (curr == prev - 1 && lower[i].isLetterOrDigit() && lower[i - 1].isLetterOrDigit()) {
                descRun++
                if (descRun >= minRun) return true
            } else {
                descRun = 1
            }
        }
        return false
    }

    private fun hasRepeatedCharacters(input: String, minRepeat: Int): Boolean {
        if (input.length < minRepeat) return false
        var run = 1
        for (i in 1 until input.length) {
            if (input[i] == input[i - 1]) {
                run++
                if (run >= minRepeat) return true
            } else {
                run = 1
            }
        }
        return false
    }
}
