# PRIVATE VAULT ProGuard / R8 Configuration (PV-SEC-012)
-keepattributes SourceFile,LineNumberTable,Signature,InnerClasses,EnclosingMethod,*Annotation*

# Room SQLite Database, DAO, and Entities
-keep class * extends androidx.room.RoomDatabase { *; }
-keep @androidx.room.Entity class * { *; }
-keep @androidx.room.Dao class * { *; }
-keep class com.example.data.*Entity { *; }
-keep class com.example.data.PrivateVaultDatabase* { *; }
-dontwarn androidx.room.paging.**

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

# Keep Kotlin Coroutines & Compose runtime metadata
-dontwarn kotlinx.coroutines.**
