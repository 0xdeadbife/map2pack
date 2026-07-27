package com.deadbife.map2pack

/**
 * Mutable configuration shared between the UI and the HttpHandler.
 * Fields are @Volatile because they are read from proxy threads and
 * written from the Swing Event Dispatch Thread.
 */
class Config {
    @Volatile var enabled: Boolean = true

    /** Only analyze URLs that are in Burp's scope. */
    @Volatile var inScopeOnly: Boolean = false

    /**
     * When a .js does not declare sourceMappingURL, still probe <url>.map
     * (the "guess the source map" technique).
     */
    @Volatile var guessMaps: Boolean = true

    /** Also report when only a webpack runtime is detected (no source map). */
    @Volatile var reportWebpackRuntime: Boolean = true

    /**
     * Command used to open recovered sources. Just the executable or full path
     * (e.g. code, codium, subl, /usr/bin/code); the file/folder is passed as an
     * argument, so it stays editor- and OS-agnostic.
     */
    @Volatile var editorCommand: String = "code"

    /** Skip responses larger than this size (bytes) to avoid slowing the proxy. */
    @Volatile var maxBodyBytes: Int = 20 * 1024 * 1024
}
