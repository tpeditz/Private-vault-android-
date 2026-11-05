# PRIVATE VAULT ProGuard / R8 Configuration (R17)
-keepattributes SourceFile,LineNumberTable,Signature,InnerClasses,EnclosingMethod,*Annotation*

# Room database & entities
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class *
-keep @androidx.room.Dao class *
-dontwarn androidx.room.paging.**

# BouncyCastle Argon2id provider classes
-keep class org.bouncycastle.crypto.generators.Argon2BytesGenerator { *; }
-keep class org.bouncycastle.crypto.params.Argon2Parameters* { *; }
-dontwarn org.bouncycastle.**

# Android APK Signature Verifier (apksig)
-keep class com.android.apksig.** { *; }
-dontwarn com.android.apksig.**

# Keep Kotlin Coroutines & Compose runtime metadata
-dontwarn kotlinx.coroutines.**
