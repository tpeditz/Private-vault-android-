package com.example.security

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Manages hardware-backed Android Keystore wrapping of the Real Vault DEK when Decoy Mode is disabled.
 *
 * Security Rules (Section 14 & 15):
 * - Biometric unlock is ONLY permitted when Decoy Mode is disabled.
 * - Enabling Decoy Mode immediately deletes the Keystore key and wipes any biometric wrapper bytes.
 * - BiometricPrompt must authenticate a cryptographic Cipher object, never a boolean UI callback.
 */
class BiometricKeystoreManager(private val context: Context) {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS_REAL_VAULT_BIO = "com.tpeditz.privatevault.real_bio_kek_v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
    }

    enum class BiometricHardwareStatus {
        AVAILABLE,
        NO_HARDWARE,
        HARDWARE_UNAVAILABLE,
        NONE_ENROLLED,
        UNSUPPORTED
    }

    fun checkBiometricAvailability(): BiometricHardwareStatus {
        val manager = BiometricManager.from(context)
        return when (manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> BiometricHardwareStatus.AVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> BiometricHardwareStatus.NO_HARDWARE
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> BiometricHardwareStatus.HARDWARE_UNAVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BiometricHardwareStatus.NONE_ENROLLED
            else -> BiometricHardwareStatus.UNSUPPORTED
        }
    }

    /**
     * Generates a fresh user-authenticated AES-256-GCM key in Android Keystore and returns
     * an initialized ENCRYPT_MODE Cipher for BiometricPrompt.CryptoObject.
     */
    fun createEncryptionCipherForBiometricEnrollment(): Cipher {
        deleteBiometricKey()
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS_REAL_VAULT_BIO,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            builder.setInvalidatedByBiometricEnrollment(true)
        }

        keyGenerator.init(builder.build())
        val secretKey = keyGenerator.generateKey()

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipher
    }

    /**
     * Initializes a DECRYPT_MODE Cipher for BiometricPrompt.CryptoObject using the stored nonce.
     * Throws KeyPermanentlyInvalidatedException if a new fingerprint/biometric was enrolled.
     */
    @Throws(KeyPermanentlyInvalidatedException::class, Exception::class)
    fun createDecryptionCipher(iv: ByteArray): Cipher {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val secretKey = keyStore.getKey(KEY_ALIAS_REAL_VAULT_BIO, null) as? SecretKey
            ?: throw IllegalStateException("Biometric Keystore key is not present.")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher
    }

    /**
     * Deletes the biometric wrapping key from Android Keystore.
     * Called whenever Decoy Mode is enabled, biometrics are disabled, or key invalidation occurs.
     */
    fun deleteBiometricKey() {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (keyStore.containsAlias(KEY_ALIAS_REAL_VAULT_BIO)) {
                keyStore.deleteEntry(KEY_ALIAS_REAL_VAULT_BIO)
            }
        } catch (_: Exception) {
            // Best-effort cleanup on JVM/Robolectric where AndroidKeyStore may not be mounted
        }
    }
}
