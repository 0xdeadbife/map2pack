package com.deadbife.map2pack

import burp.api.montoya.MontoyaApi

/**
 * Persists [Config] via Burp's extension-level preferences, which survive
 * project changes and restarts.
 */
class Settings(api: MontoyaApi, private val config: Config) {

    private val prefs = api.persistence().preferences()

    fun load() {
        prefs.getString(KEY_EDITOR)?.let { config.editorCommand = it }
        prefs.getBoolean(KEY_ENABLED)?.let { config.enabled = it }
        prefs.getBoolean(KEY_SCOPE)?.let { config.inScopeOnly = it }
        prefs.getBoolean(KEY_GUESS)?.let { config.guessMaps = it }
        prefs.getBoolean(KEY_WEBPACK)?.let { config.reportWebpackRuntime = it }
    }

    fun saveEditorCommand() = prefs.setString(KEY_EDITOR, config.editorCommand)

    fun saveToggles() {
        prefs.setBoolean(KEY_ENABLED, config.enabled)
        prefs.setBoolean(KEY_SCOPE, config.inScopeOnly)
        prefs.setBoolean(KEY_GUESS, config.guessMaps)
        prefs.setBoolean(KEY_WEBPACK, config.reportWebpackRuntime)
    }

    private companion object {
        const val KEY_EDITOR = "editorCommand"
        const val KEY_ENABLED = "enabled"
        const val KEY_SCOPE = "inScopeOnly"
        const val KEY_GUESS = "guessMaps"
        const val KEY_WEBPACK = "reportWebpackRuntime"
    }
}
