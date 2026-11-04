package com.example.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

private val DarkColorScheme = darkColorScheme(
    primary = EmeraldPrimaryDark,
    onPrimary = EmeraldOnPrimaryDark,
    primaryContainer = EmeraldContainerDark,
    onPrimaryContainer = EmeraldOnContainerDark,
    secondary = TealSecondaryDark,
    onSecondary = Color(0xFF00201D),
    secondaryContainer = TealContainerDark,
    onSecondaryContainer = Color(0xFF99F6E4),
    tertiary = Color(0xFF38BDF8),
    background = ObsidianBackground,
    onBackground = SlateOnBackgroundDark,
    surface = ObsidianSurface,
    onSurface = SlateOnBackgroundDark,
    surfaceVariant = ObsidianSurfaceVariant,
    onSurfaceVariant = SlateOnSurfaceVariantDark,
    outline = ObsidianOutline,
    error = StatusVeryWeak,
    onError = Color.White
)

private val LightColorScheme = lightColorScheme(
    primary = EmeraldPrimaryLight,
    onPrimary = EmeraldOnPrimaryLight,
    primaryContainer = EmeraldContainerLight,
    onPrimaryContainer = EmeraldOnContainerLight,
    secondary = TealSecondaryLight,
    onSecondary = Color.White,
    secondaryContainer = TealContainerLight,
    onSecondaryContainer = Color(0xFF134E4A),
    tertiary = Color(0xFF0284C7),
    background = AlabasterBackground,
    onBackground = SlateOnBackgroundLight,
    surface = AlabasterSurface,
    onSurface = SlateOnBackgroundLight,
    surfaceVariant = AlabasterSurfaceVariant,
    onSurfaceVariant = SlateOnSurfaceVariantLight,
    outline = AlabasterOutline,
    error = Color(0xFFDC2626),
    onError = Color.White
)

val VaultShapes = Shapes(
    extraSmall = RoundedCornerShape(6.dp),
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(14.dp),
    large = RoundedCornerShape(20.dp),
    extraLarge = RoundedCornerShape(28.dp)
)

enum class AppThemeMode {
    SYSTEM,
    DARK,
    LIGHT
}

@Composable
fun PrivateVaultTheme(
    themeMode: AppThemeMode = AppThemeMode.DARK,
    content: @Composable () -> Unit
) {
    val useDarkTheme = when (themeMode) {
        AppThemeMode.SYSTEM -> isSystemInDarkTheme()
        AppThemeMode.DARK -> true
        AppThemeMode.LIGHT -> false
    }

    val colorScheme = if (useDarkTheme) DarkColorScheme else LightColorScheme

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        shapes = VaultShapes,
        content = content
    )
}
