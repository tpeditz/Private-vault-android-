# PRIVATE VAULT ProGuard / R8 Configuration (PV-SEC-012 & Task 2 Release Hardening)
-keepattributes SourceFile,LineNumberTable,Signature,InnerClasses,EnclosingMethod,*Annotation*

# Room SQLite Database, DAO, and Entities (v1..v4 including EncryptedMediaFileEntity)
-keep class * extends androidx.room.RoomDatabase { *; }
-keep @androidx.room.Entity class * { *; }
-keep @androidx.room.Dao class * { *; }
-keep class com.example.data.*Entity { *; }
-keep class com.example.data.PrivateVaultDatabase* { *; }
-dontwarn androidx.room.paging.**

# Keep Android MediaDataSource subclasses used for in-memory encrypted video playback
-keep class * extends android.media.MediaDataSource { *; }

# BouncyCastle Argon2id v1.3 & JCA Cryptography
-keep class org.bouncycastle.crypto.generators.Argon2BytesGenerator { *; }
-keep class org.bouncycastle.crypto.params.Argon2Parameters* { *; }
-keep class org.bouncycastle.crypto.digests.** { *; }
-dontwarn org.bouncycastle.**

# Android APK Signature Verifier (apksig)
-keep class com.android.apksig.** { *; }
-dontwarn com.android.apksig.**

# OkHttp & Okio
-dontwarn okhttp3.**
-dontwarn okio.**
-dontwarn javax.annotation.**
-dontwarn org.conscrypt.**
-dontwarn org.openjsse.**
-dontwarn org.bouncycastle.jsse.**

# Strip verbose and debug logs in release while retaining safe sanitized warnings/errors
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}

# Keep Kotlin Coroutines & Compose runtime metadata
-dontwarn kotlinx.coroutines.**
