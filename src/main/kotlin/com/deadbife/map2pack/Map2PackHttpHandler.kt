package com.deadbife.map2pack

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import com.deadbife.map2pack.ui.Map2PackTab
import java.net.URI
import java.time.LocalTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

class Map2PackHttpHandler(
    private val api: MontoyaApi,
    private val config: Config,
    private val ui: Map2PackTab
) : HttpHandler {

    private val executor = Executors.newFixedThreadPool(4)
    private val counter = AtomicInteger(0)
    private val timeFmt = DateTimeFormatter.ofPattern("HH:mm:ss")

    // Marker header so we never re-analyze our own .map probes.
    private val markerHeader = "X-Map2Pack-Scan"

    // Dedupe: JS URLs already analyzed and maps/findings already reported.
    private val analyzedJs = ConcurrentHashMap.newKeySet<String>()
    private val reported = ConcurrentHashMap.newKeySet<String>()

    override fun handleHttpRequestToBeSent(req: HttpRequestToBeSent): RequestToBeSentAction =
        RequestToBeSentAction.continueWith(req)

    override fun handleHttpResponseReceived(resp: HttpResponseReceived): ResponseReceivedAction {
        if (config.enabled) {
            try {
                maybeQueue(resp)
            } catch (e: Exception) {
                api.logging().logToError("[map2pack] handler: ${e.message}")
            }
        }
        return ResponseReceivedAction.continueWith(resp)
    }

    private fun maybeQueue(resp: HttpResponseReceived) {
        val initiating = resp.initiatingRequest()
        // Ignore our own probe requests.
        if (initiating.hasHeader(markerHeader)) return
        if (resp.statusCode().toInt() != 200) return

        val url = initiating.url()
        val lower = url.lowercase()
        // .map responses are handled by direct fetch, not as JS inputs.
        if (lower.substringBefore('?').endsWith(".map")) return

        val contentType = resp.headerValue("Content-Type")?.lowercase() ?: ""
        val looksJs = lower.substringBefore('?').endsWith(".js") ||
            contentType.contains("javascript") ||
            contentType.contains("ecmascript")
        if (!looksJs) return

        if (config.inScopeOnly && !api.scope().isInScope(url)) return
        if (!analyzedJs.add(url)) return

        // Copy what we need and process off the proxy thread.
        val body = resp.bodyToString()
        if (body.length > config.maxBodyBytes) return
        val pair = HttpRequestResponse.httpRequestResponse(initiating, resp)
        executor.submit { analyze(url, body, initiating, pair) }
    }

    private fun analyze(
        jsUrl: String,
        body: String,
        jsRequest: HttpRequest,
        jsPair: HttpRequestResponse
    ) {
        val hasWebpack = SourceMapAnalyzer.hasWebpackRuntime(body)
        val mapRef = SourceMapAnalyzer.findSourceMappingUrl(body)

        when {
            mapRef != null && SourceMapAnalyzer.isDataUri(mapRef) -> {
                val json = SourceMapAnalyzer.decodeDataUri(mapRef)
                if (json != null && SourceMapAnalyzer.looksLikeSourceMap(json)) {
                    val parsed = SourceMapAnalyzer.parseMap(json)
                    if (parsed != null) {
                        report(Method.INLINE_SOURCEMAP, jsUrl, null, parsed, hasWebpack,
                            status = "inline map", evidence = listOf(jsPair))
                        return
                    }
                }
            }
            mapRef != null -> {
                val mapUrl = SourceMapAnalyzer.resolveMapUrl(jsUrl, mapRef)
                if (mapUrl != null) {
                    fetchAndReport(Method.SOURCEMAP_COMMENT, jsUrl, mapUrl, jsRequest, jsPair, hasWebpack)
                    return
                }
            }
            config.guessMaps -> {
                val guess = jsUrl.substringBefore('?') + ".map"
                fetchAndReport(Method.GUESSED_MAP, jsUrl, guess, jsRequest, jsPair, hasWebpack, silentOnMiss = true)
                return
            }
        }

        if (hasWebpack && config.reportWebpackRuntime) {
            reportWebpackOnly(jsUrl, jsPair)
        }
    }

    private fun fetchAndReport(
        method: Method,
        jsUrl: String,
        mapUrl: String,
        jsRequest: HttpRequest,
        jsPair: HttpRequestResponse,
        hasWebpack: Boolean,
        silentOnMiss: Boolean = false
    ) {
        val mapReq = buildMapRequest(jsRequest, mapUrl) ?: return
        val mapRR = try {
            api.http().sendRequest(mapReq)
        } catch (e: Exception) {
            api.logging().logToError("[map2pack] fetch map $mapUrl: ${e.message}")
            null
        }

        val mapResp = mapRR?.response()
        val code = mapResp?.statusCode()?.toInt() ?: 0
        val mapBody = mapResp?.bodyToString() ?: ""

        if (code == 200 && SourceMapAnalyzer.looksLikeSourceMap(mapBody)) {
            val parsed = SourceMapAnalyzer.parseMap(mapBody)
            if (parsed != null) {
                report(method, jsUrl, mapUrl, parsed, hasWebpack,
                    status = "map 200 (${parsed.recoverableCount}/${parsed.sources.size})",
                    evidence = listOfNotNull(jsPair, mapRR))
                return
            }
        }

        // The map exists as a reference but no code could be recovered.
        if (!silentOnMiss && method == Method.SOURCEMAP_COMMENT) {
            reportMissingMap(jsUrl, mapUrl, code, jsPair)
        } else if (hasWebpack && config.reportWebpackRuntime) {
            reportWebpackOnly(jsUrl, jsPair)
        }
    }

    /** Builds the .map request reusing the .js session when it is the same host. */
    private fun buildMapRequest(jsRequest: HttpRequest, mapUrl: String): HttpRequest? {
        return try {
            val service = jsRequest.httpService()
            val u = URI(mapUrl)
            val scheme = u.scheme ?: if (service.secure()) "https" else "http"
            val port = if (u.port != -1) u.port else if (scheme == "https") 443 else 80
            val sameService = u.host.equals(service.host(), ignoreCase = true) &&
                port == service.port() &&
                scheme.equals(if (service.secure()) "https" else "http", ignoreCase = true)

            val base = if (sameService) {
                val pathAndQuery = buildString {
                    append(u.rawPath ?: "/")
                    if (u.rawQuery != null) append('?').append(u.rawQuery)
                }
                jsRequest.withPath(pathAndQuery)
            } else {
                HttpRequest.httpRequestFromUrl(mapUrl)
            }
            base.withAddedHeader(markerHeader, "1")
        } catch (e: Exception) {
            api.logging().logToError("[map2pack] buildMapRequest $mapUrl: ${e.message}")
            null
        }
    }

    private fun report(
        method: Method,
        jsUrl: String,
        mapUrl: String?,
        parsed: ParsedMap,
        hasWebpack: Boolean,
        status: String,
        evidence: List<HttpRequestResponse>
    ) {
        val key = "map:" + (mapUrl ?: jsUrl)
        if (!reported.add(key)) return

        val recoverable = parsed.recoverableCount > 0
        val severity = if (recoverable) AuditIssueSeverity.MEDIUM else AuditIssueSeverity.LOW
        val confidence = AuditIssueConfidence.CERTAIN
        val host = hostOf(jsUrl)

        val detail = buildString {
            append("<b>Detection method:</b> ${method.label}<br>")
            append("<b>Script:</b> ${esc(jsUrl)}<br>")
            if (mapUrl != null) append("<b>Source map:</b> ${esc(mapUrl)}<br>")
            append("<b>Declared sources:</b> ${parsed.sources.size}<br>")
            append("<b>Sources with recoverable code:</b> ${parsed.recoverableCount}<br>")
            append("<b>Webpack runtime:</b> ${if (hasWebpack || parsed.looksWebpack) "yes" else "no"}<br><br>")
            if (recoverable) {
                append("The source map embeds <code>sourcesContent</code>, so the original ")
                append("application source code can be reconstructed. Sample files:<br>")
                append("<ul>")
                parsed.sources.take(15).forEach { append("<li>${esc(it)}</li>") }
                append("</ul>")
                if (parsed.sources.size > 15) append("... and ${parsed.sources.size - 15} more.")
            } else {
                append("The source map is reachable but does not embed <code>sourcesContent</code>; ")
                append("it exposes internal paths/structure but not the full code.")
            }
        }

        val d = Detection(
            index = counter.incrementAndGet(),
            time = LocalTime.now().format(timeFmt),
            method = method,
            host = host,
            jsUrl = jsUrl,
            mapUrl = mapUrl,
            status = status,
            sourceCount = parsed.sources.size,
            recoverableCount = parsed.recoverableCount,
            hasWebpack = hasWebpack || parsed.looksWebpack,
            severity = severity,
            confidence = confidence,
            detail = detail.replace("<br>", "\n").replace(Regex("<[^>]+>"), ""),
            sources = parsed.sources,
            sourcesContent = parsed.sourcesContent
        )
        ui.addDetection(d)

        raiseIssue(
            name = if (recoverable) "Source code exposed via source map" else "Source map is publicly accessible",
            detail = detail,
            baseUrl = jsUrl,
            severity = severity,
            confidence = confidence,
            evidence = evidence
        )
    }

    private fun reportMissingMap(jsUrl: String, mapUrl: String, code: Int, jsPair: HttpRequestResponse) {
        val key = "ref:$mapUrl"
        if (!reported.add(key)) return
        val detail = "The script declares <b>sourceMappingURL</b> pointing to ${esc(mapUrl)} " +
            "but the request returned HTTP $code. The reference is still an indicator of a source map."
        val d = Detection(
            index = counter.incrementAndGet(),
            time = LocalTime.now().format(timeFmt),
            method = Method.SOURCEMAP_COMMENT,
            host = hostOf(jsUrl),
            jsUrl = jsUrl,
            mapUrl = mapUrl,
            status = "map $code",
            sourceCount = 0,
            recoverableCount = 0,
            hasWebpack = false,
            severity = AuditIssueSeverity.INFORMATION,
            confidence = AuditIssueConfidence.FIRM,
            detail = detail.replace(Regex("<[^>]+>"), ""),
            sources = emptyList(),
            sourcesContent = emptyList()
        )
        ui.addDetection(d)
        raiseIssue(
            "Source map reference detected", detail, jsUrl,
            AuditIssueSeverity.INFORMATION, AuditIssueConfidence.FIRM, listOf(jsPair)
        )
    }

    private fun reportWebpackOnly(jsUrl: String, jsPair: HttpRequestResponse) {
        val key = "wp:$jsUrl"
        if (!reported.add(key)) return
        val detail = "The script contains <b>webpack</b> runtime patterns " +
            "(webpackJsonp / __webpack_require__ / webpackChunk). No reachable source map was found, " +
            "but the bundle may be analyzable with unpacking tools."
        val d = Detection(
            index = counter.incrementAndGet(),
            time = LocalTime.now().format(timeFmt),
            method = Method.WEBPACK_RUNTIME,
            host = hostOf(jsUrl),
            jsUrl = jsUrl,
            mapUrl = null,
            status = "webpack",
            sourceCount = 0,
            recoverableCount = 0,
            hasWebpack = true,
            severity = AuditIssueSeverity.INFORMATION,
            confidence = AuditIssueConfidence.FIRM,
            detail = detail.replace(Regex("<[^>]+>"), ""),
            sources = emptyList(),
            sourcesContent = emptyList()
        )
        ui.addDetection(d)
        raiseIssue(
            "Webpack bundle detected", detail, jsUrl,
            AuditIssueSeverity.INFORMATION, AuditIssueConfidence.FIRM, listOf(jsPair)
        )
    }

    private fun raiseIssue(
        name: String,
        detail: String,
        baseUrl: String,
        severity: AuditIssueSeverity,
        confidence: AuditIssueConfidence,
        evidence: List<HttpRequestResponse>
    ) {
        try {
            val issue = AuditIssue.auditIssue(
                name,
                detail,
                "Disable source map (.map) deployment and remove sourceMappingURL references " +
                    "in production. Serve minified code without maps.",
                baseUrl,
                severity,
                confidence,
                "Source maps allow reconstructing the original source code from minified bundles, " +
                    "exposing business logic, internal paths, comments and potential secrets.",
                "Configure the bundler (webpack/vite/etc.) to not emit source maps in production, " +
                    "or restrict access to them.",
                severity,
                *evidence.toTypedArray()
            )
            api.siteMap().add(issue)
        } catch (e: Exception) {
            api.logging().logToError("[map2pack] raiseIssue: ${e.message}")
        }
    }

    private fun hostOf(url: String): String = try {
        URI(url).host ?: url
    } catch (e: Exception) {
        url
    }

    private fun esc(s: String): String =
        s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    fun shutdown() {
        executor.shutdownNow()
    }
}
