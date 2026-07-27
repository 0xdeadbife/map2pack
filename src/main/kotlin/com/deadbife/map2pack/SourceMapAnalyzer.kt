package com.deadbife.map2pack

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.Base64

data class ParsedMap(
    val sources: List<String>,
    val sourcesContent: List<String?>,
    val recoverableCount: Int,
    val looksWebpack: Boolean
)

@Serializable
private data class RawSourceMap(
    val version: Int? = null,
    val sources: List<String?> = emptyList(),
    @SerialName("sourcesContent") val sourcesContent: List<String?>? = null,
    val mappings: String? = null
)

object SourceMapAnalyzer {

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    // //# sourceMappingURL=...  //@ ...  /*# ... */ (every form bundlers emit)
    private val SOURCE_MAP_URL = Regex("""sourceMappingURL=([^\s'")*]+)""")

    private val WEBPACK_HINTS = listOf(
        "webpackJsonp",
        "webpackChunk",
        "__webpack_require__",
        "__webpack_modules__",
        "webpack://"
    )

    fun findSourceMappingUrl(body: String): String? =
        SOURCE_MAP_URL.findAll(body).lastOrNull()?.groupValues?.get(1)?.trim()

    fun hasWebpackRuntime(body: String): Boolean =
        WEBPACK_HINTS.any { body.contains(it) }

    fun isDataUri(value: String): Boolean = value.startsWith("data:")

    fun decodeDataUri(value: String): String? {
        if (!value.startsWith("data:")) return null
        val comma = value.indexOf(',')
        if (comma < 0) return null
        val meta = value.substring(5, comma)
        val data = value.substring(comma + 1)
        return try {
            if (meta.contains("base64", ignoreCase = true)) {
                String(Base64.getDecoder().decode(data.trim()), StandardCharsets.UTF_8)
            } else {
                URLDecoder.decode(data, StandardCharsets.UTF_8)
            }
        } catch (e: Exception) {
            null
        }
    }

    fun resolveMapUrl(jsUrl: String, mapRef: String): String? = try {
        URI(jsUrl).resolve(mapRef).toString()
    } catch (e: Exception) {
        null
    }

    // Cheap: discards SPA fallback HTML before attempting to deserialize.
    fun looksLikeSourceMap(body: String): Boolean {
        val t = body.trimStart()
        if (!t.startsWith("{")) return false
        return t.contains("\"version\"") && (t.contains("\"sources\"") || t.contains("\"mappings\""))
    }

    fun parseMap(body: String): ParsedMap? {
        val raw = try {
            json.decodeFromString<RawSourceMap>(body)
        } catch (e: Exception) {
            return null
        }
        val sources = raw.sources.map { it ?: "" }
        val contents = ArrayList<String?>(raw.sourcesContent ?: emptyList())
        while (contents.size < sources.size) contents.add(null)

        val recoverable = contents.count { !it.isNullOrEmpty() }
        val looksWebpack = sources.any { it.startsWith("webpack:") }
        return ParsedMap(sources, contents, recoverable, looksWebpack)
    }

    // webpack:// / schemes / ../ produce unsafe paths for writing to disk.
    fun sanitizeSourcePath(raw: String): String {
        var p = raw
        p = p.removePrefix("webpack://")
        p = p.replaceFirst(Regex("^[a-zA-Z][a-zA-Z0-9+.-]*://"), "")
        p = p.substringBefore('?').substringBefore('#')
        val parts = p.split('/')
            .filter { it.isNotEmpty() && it != ".." && it != "." }
            .map { seg -> seg.replace(Regex("[^A-Za-z0-9._@+~\\-]"), "_") }
        return parts.joinToString("/").ifBlank { "unknown_source" }
    }
}
