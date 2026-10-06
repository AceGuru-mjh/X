package com.unknown.security.core.model

/** App appearance preference, persisted in settings. */
enum class ThemeMode(
    val key: String,
    val label: String,
) {
    SYSTEM("system", "跟随系统"),
    LIGHT("light", "浅色"),
    DARK("dark", "深色"),
    ;

    companion object {
        fun fromKey(key: String?): ThemeMode = entries.firstOrNull { it.key == key } ?: SYSTEM
    }
}
