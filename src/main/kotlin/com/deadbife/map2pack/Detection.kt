package com.deadbife.map2pack

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity

/** How the source map / code was discovered. */
enum class Method(val label: String) {
    SOURCEMAP_COMMENT("sourceMappingURL"),
    INLINE_SOURCEMAP("inline data: map"),
    GUESSED_MAP("guessed .map"),
    WEBPACK_RUNTIME("webpack runtime")
}

/**
 * A single finding. Holds what the UI needs to render the row, what the
 * exporter needs to recover the code, and what feeds the AuditIssue.
 */
data class Detection(
    val index: Int,
    val time: String,
    val method: Method,
    val host: String,
    val jsUrl: String,
    val mapUrl: String?,
    val status: String,
    val sourceCount: Int,
    val recoverableCount: Int,
    val hasWebpack: Boolean,
    val severity: AuditIssueSeverity,
    val confidence: AuditIssueConfidence,
    val detail: String,
    /** Paths declared in the source map (parallel to [sourcesContent]). */
    val sources: List<String>,
    /** Content of each source, null when the map does not embed it. */
    val sourcesContent: List<String?>
) {
    /** True when original source code can actually be written back to disk. */
    val recoverable: Boolean get() = recoverableCount > 0
}
