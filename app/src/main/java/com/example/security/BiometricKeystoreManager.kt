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
 * Security Rules:
 * - Biometric unlock is ONLY permitted when Decoy Mode is disabled.
 * - Enabling Decoy Mode immediately deletes the Keystore key and wipes any biometric wrapper bytes.
 * - BiometricPrompt must authenticate a cryptographic Cipher object, never a boolean UI callback.
 */
object BiometricKeyEnvelopeHelper {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS_REAL_VAULT_BIO = "com.tpeditz.privatevault.real_bio_kek_v1"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128

    data class WrappedBiometricDek(
        val iv: ByteArray,
        val ciphertext: ByteArray
    )

    fun hasHardwareKey(): Boolean {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            keyStore.containsAlias(KEY_ALIAS_REAL_VAULT_BIO)
        } catch (_: Exception) {
            false
        }
    }

    fun getEncryptCipherForEnrollment(): Cipher? {
        return try {
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
            cipher
        } catch (_: Exception) {
            null
        }
    }

    fun wrapDekWithAuthenticatedCipher(
        authenticatedCipher: Cipher,
        dekBytes: ByteArray
    ): WrappedBiometricDek {
        val ciphertext = authenticatedCipher.doFinal(dekBytes)
        val iv = authenticatedCipher.iv
            ?: throw IllegalStateException("Authenticated biometric cipher did not provide an IV.")
        return WrappedBiometricDek(iv = iv, ciphertext = ciphertext)
    }

    fun getDecryptCipherForUnlock(iv: ByteArray): Cipher? {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val secretKey = keyStore.getKey(KEY_ALIAS_REAL_VAULT_BIO, null) as? SecretKey
                ?: return null
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_BITS, iv))
            cipher
        } catch (_: KeyPermanentlyInvalidatedException) {
            deleteBiometricKey()
            null
        } catch (_: Exception) {
            null
        }
    }

    fun unwrapDekWithAuthenticatedCipher(
        authenticatedCipher: Cipher,
        ciphertext: ByteArray
    ): ByteArray {
        return authenticatedCipher.doFinal(ciphertext)
    }

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

class BiometricKeystoreManager(private val context: Context) {

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
}
