package com.deadbife.map2pack.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.ui.editor.EditorOptions
import com.deadbife.map2pack.Config
import com.deadbife.map2pack.Detection
import com.deadbife.map2pack.Method
import com.deadbife.map2pack.Settings
import com.deadbife.map2pack.SourceMapAnalyzer
import java.awt.BorderLayout
import java.awt.Desktop
import java.awt.FlowLayout
import java.awt.Font
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.awt.event.ActionEvent
import java.awt.event.KeyEvent
import java.io.File
import javax.swing.AbstractAction
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComponent
import javax.swing.JFileChooser
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSeparator
import javax.swing.JSplitPane
import javax.swing.JTable
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.KeyStroke
import javax.swing.ListSelectionModel
import javax.swing.SwingUtilities
import javax.swing.table.AbstractTableModel

class Map2PackTab(
    private val api: MontoyaApi,
    private val config: Config,
    private val settings: Settings
) {
    val component: JPanel = JPanel(BorderLayout())

    // Spacing derived from the theme font size so it scales with Burp's settings.
    private val pad = api.userInterface().currentDisplayFont().size.coerceIn(8, 24)

    private val detections = ArrayList<Detection>()
    private val findingsModel = FindingsTableModel(detections)
    private val findingsTable = JTable(findingsModel)

    private val sourcesModel = SourcesTableModel()
    private val sourcesTable = JTable(sourcesModel)

    // Native response editor: its Pretty view gives JS/JSON/CSS syntax highlighting.
    private val previewEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY)

    // Summary header fields, updated on selection instead of rebuilt.
    private val sevValue = JLabel()
    private val methodValue = JLabel()
    private val countsValue = JLabel()
    private val webpackValue = JLabel()
    private val scriptValue = readOnlyField()
    private val mapValue = readOnlyField()
    private val descValue = wrappedText()

    private val saveFileButton = JButton("Save file...")
    private val openEditorButton = JButton("Open in editor")
    private val openAllButton = JButton("Open all in editor")
    private val copyPathButton = JButton("Copy path")

    // Caption labels get bolded after theming (Burp's L&F disables HTML in labels).
    private val captionLabels = ArrayList<JLabel>()

    private var current: Detection? = null

    init {
        buildUi()
    }

    private fun buildUi() {
        component.add(buildTopBar(), BorderLayout.NORTH)
        component.add(buildCenterSplit(), BorderLayout.CENTER)
        clearDetail()
        api.userInterface().applyThemeToComponent(component)
        // Bold captions using the theme font resolved by applyThemeToComponent.
        captionLabels.forEach { it.font = it.font.deriveFont(Font.BOLD) }
    }

    private fun buildTopBar(): JComponent {
        val toggles = JPanel(FlowLayout(FlowLayout.LEFT, pad, pad / 2))
        toggles.add(JCheckBox("Enabled", config.enabled).apply {
            addActionListener { config.enabled = isSelected; settings.saveToggles() }
        })
        toggles.add(JCheckBox("In-scope only", config.inScopeOnly).apply {
            addActionListener { config.inScopeOnly = isSelected; settings.saveToggles() }
        })
        toggles.add(JCheckBox("Guess .js.map", config.guessMaps).apply {
            addActionListener { config.guessMaps = isSelected; settings.saveToggles() }
        })
        toggles.add(JCheckBox("Report webpack runtime", config.reportWebpackRuntime).apply {
            addActionListener { config.reportWebpackRuntime = isSelected; settings.saveToggles() }
        })
        toggles.add(JButton("Settings...").apply {
            addActionListener { openSettings() }
        })

        val actions = JPanel(FlowLayout(FlowLayout.RIGHT, pad / 2, pad / 2))
        actions.add(JButton("Export all sources...").apply {
            addActionListener { exportAll() }
        })
        actions.add(JButton("Delete selected").apply {
            addActionListener { deleteSelected() }
        })
        actions.add(JButton("Clear").apply {
            addActionListener { clearAll() }
        })

        val row = JPanel(BorderLayout())
        row.add(toggles, BorderLayout.WEST)
        row.add(actions, BorderLayout.EAST)

        return JPanel(BorderLayout()).apply {
            add(row, BorderLayout.CENTER)
            add(JSeparator(), BorderLayout.SOUTH)
        }
    }

    private fun buildCenterSplit(): JSplitPane {
        findingsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        findingsTable.autoResizeMode = JTable.AUTO_RESIZE_OFF
        findingsTable.autoCreateRowSorter = true
        findingsTable.fillsViewportHeight = true
        findingsTable.selectionModel.addListSelectionListener {
            if (!it.valueIsAdjusting) showDetail()
        }
        findingsTable.inputMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0), "deleteFindings")
        findingsTable.actionMap.put("deleteFindings", object : AbstractAction() {
            override fun actionPerformed(e: ActionEvent?) = deleteSelected()
        })
        setFindingsWidths()

        val top = JScrollPane(findingsTable).apply { border = emptyBorder() }

        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top, buildDetailPanel())
        split.resizeWeight = 0.55
        split.isOneTouchExpandable = true
        split.border = emptyBorder()
        return split
    }

    private fun buildDetailPanel(): JComponent {
        val panel = JPanel(BorderLayout())
        panel.border = emptyBorder()
        panel.add(buildSummary(), BorderLayout.NORTH)
        panel.add(buildSourcesSplit(), BorderLayout.CENTER)
        return panel
    }

    private fun buildSummary(): JComponent {
        val p = JPanel(GridBagLayout())
        p.border = BorderFactory.createEmptyBorder(pad / 2, pad, pad / 2, pad)

        p.add(caption("Severity"), gbc(0, 0))
        p.add(sevValue, gbc(1, 0))
        p.add(caption("Method"), gbc(2, 0))
        p.add(methodValue, gbc(3, 0))
        p.add(Box.createHorizontalGlue(), gbc(4, 0, weightx = 1.0))

        p.add(caption("Recoverable"), gbc(0, 1))
        p.add(countsValue, gbc(1, 1))
        p.add(caption("Webpack"), gbc(2, 1))
        p.add(webpackValue, gbc(3, 1))

        p.add(caption("Script"), gbc(0, 2))
        p.add(scriptValue, gbc(1, 2, width = 4, weightx = 1.0))
        p.add(caption("Map"), gbc(0, 3))
        p.add(mapValue, gbc(1, 3, width = 4, weightx = 1.0))

        p.add(descValue, gbc(0, 4, width = 5, weightx = 1.0))
        return p
    }

    private fun buildSourcesSplit(): JComponent {
        sourcesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        sourcesTable.autoCreateRowSorter = true
        sourcesTable.fillsViewportHeight = true
        sourcesTable.columnModel.getColumn(0).preferredWidth = 260
        sourcesTable.columnModel.getColumn(1).preferredWidth = 60
        sourcesTable.selectionModel.addListSelectionListener {
            if (!it.valueIsAdjusting) showSource()
        }

        val actions = JPanel(FlowLayout(FlowLayout.LEFT, pad / 2, pad / 2)).apply {
            add(saveFileButton.apply { addActionListener { saveSelectedFile() } })
            add(openEditorButton.apply { addActionListener { openSelectedInEditor() } })
            add(openAllButton.apply { addActionListener { openAllInEditor() } })
            add(copyPathButton.apply { addActionListener { copySelectedPath() } })
        }

        val left = JPanel(BorderLayout()).apply {
            border = BorderFactory.createTitledBorder("Sources")
            add(JScrollPane(sourcesTable), BorderLayout.CENTER)
            add(actions, BorderLayout.SOUTH)
        }
        val right = JPanel(BorderLayout()).apply {
            border = BorderFactory.createTitledBorder("Preview")
            add(previewEditor.uiComponent(), BorderLayout.CENTER)
        }

        val split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, right)
        split.resizeWeight = 0.4
        split.border = emptyBorder()
        return split
    }

    fun addDetection(d: Detection) {
        SwingUtilities.invokeLater {
            detections.add(d)
            findingsModel.fireTableRowsInserted(detections.size - 1, detections.size - 1)
        }
    }

    private fun clearAll() {
        detections.clear()
        findingsModel.fireTableDataChanged()
        clearDetail()
    }

    private fun deleteSelected() {
        val modelRows = findingsTable.selectedRows
            .map { findingsTable.convertRowIndexToModel(it) }
            .filter { it in detections.indices }
            .sortedDescending()
        if (modelRows.isEmpty()) return
        modelRows.forEach { detections.removeAt(it) }
        findingsModel.fireTableDataChanged()
        findingsTable.clearSelection()
        clearDetail()
    }

    private fun selectedFinding(): Detection? {
        val row = findingsTable.selectedRow
        if (row < 0) return null
        return detections.getOrNull(findingsTable.convertRowIndexToModel(row))
    }

    private fun showDetail() {
        val d = selectedFinding()
        if (d == null) {
            clearDetail()
            return
        }
        current = d
        sevValue.text = severityLabel(d.severity)
        methodValue.text = d.method.label
        countsValue.text = "${d.recoverableCount} / ${d.sourceCount}"
        webpackValue.text = if (d.hasWebpack) "yes" else "no"
        scriptValue.text = d.jsUrl
        scriptValue.caretPosition = 0
        mapValue.text = d.mapUrl ?: "-"
        mapValue.caretPosition = 0
        descValue.text = describe(d)

        sourcesModel.setData(d.sources, d.sourcesContent)
        previewEditor.setResponse(syntheticResponse("", "text/plain"))
        openAllButton.isEnabled = d.recoverable
        updateSourceButtons()
    }

    private fun clearDetail() {
        current = null
        sevValue.text = "-"
        methodValue.text = "-"
        countsValue.text = "-"
        webpackValue.text = "-"
        scriptValue.text = ""
        mapValue.text = ""
        descValue.text = "Select a finding to see details."
        sourcesModel.setData(emptyList(), emptyList())
        previewEditor.setResponse(syntheticResponse("", "text/plain"))
        openAllButton.isEnabled = false
        updateSourceButtons()
    }

    private fun describe(d: Detection): String = when {
        d.recoverable ->
            "The source map embeds sourcesContent; the original source code can be reconstructed."
        d.method == Method.WEBPACK_RUNTIME ->
            "Webpack runtime detected. No reachable source map, but the bundle may be unpackable."
        d.status.startsWith("map ") && d.status != "map 200" ->
            "Source map referenced but not directly accessible (${d.status})."
        else ->
            "Source map is reachable but does not embed sourcesContent (paths only, no full code)."
    }

    // ---- per-source actions ----

    private fun selectedSourceRow(): Int {
        val row = sourcesTable.selectedRow
        if (row < 0) return -1
        return sourcesTable.convertRowIndexToModel(row)
    }

    private fun showSource() {
        val row = selectedSourceRow()
        if (row < 0) {
            previewEditor.setResponse(syntheticResponse("", "text/plain"))
        } else {
            val content = sourcesModel.contentAt(row)
            val path = current?.sources?.getOrNull(row) ?: ""
            if (content.isNullOrEmpty()) {
                previewEditor.setResponse(syntheticResponse("// (no embedded content for this source)", "text/plain"))
            } else {
                previewEditor.setResponse(syntheticResponse(content, contentTypeFor(path)))
            }
        }
        updateSourceButtons()
    }

    /** Wraps recovered code in a synthetic response so the editor's Pretty view highlights it. */
    private fun syntheticResponse(body: String, contentType: String): HttpResponse =
        HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Type: $contentType\r\n\r\n").withBody(body)

    private fun contentTypeFor(path: String): String {
        val p = path.substringBefore('?').lowercase()
        return when {
            p.endsWith(".json") -> "application/json"
            p.endsWith(".css") || p.endsWith(".scss") || p.endsWith(".less") -> "text/css"
            p.endsWith(".html") || p.endsWith(".htm") || p.endsWith(".vue") -> "text/html"
            else -> "application/javascript"
        }
    }

    private fun updateSourceButtons() {
        val row = selectedSourceRow()
        val hasContent = row >= 0 && !sourcesModel.contentAt(row).isNullOrEmpty()
        saveFileButton.isEnabled = hasContent
        openEditorButton.isEnabled = hasContent
        copyPathButton.isEnabled = row >= 0
    }

    private fun saveSelectedFile() {
        val d = current ?: return
        val row = selectedSourceRow().takeIf { it >= 0 } ?: return
        val content = sourcesModel.contentAt(row) ?: return
        val suggested = SourceMapAnalyzer.sanitizeSourcePath(d.sources[row]).substringAfterLast('/')
        val chooser = JFileChooser().apply {
            dialogTitle = "Save source file"
            selectedFile = File(suggested)
        }
        if (chooser.showSaveDialog(component) != JFileChooser.APPROVE_OPTION) return
        try {
            chooser.selectedFile.writeText(content)
            api.logging().logToOutput("Saved source to ${chooser.selectedFile.absolutePath}")
        } catch (e: Exception) {
            api.logging().logToError("Error saving file: ${e.message}")
            JOptionPane.showMessageDialog(component, "Error saving file: ${e.message}")
        }
    }

    private fun openSelectedInEditor() {
        val d = current ?: return
        val row = selectedSourceRow().takeIf { it >= 0 } ?: return
        val file = stageFile(d, row) ?: return
        launchEditor(file)
    }

    private fun openAllInEditor() {
        val d = current
        if (d == null) {
            JOptionPane.showMessageDialog(component, "Select a finding first.")
            return
        }
        if (!d.recoverable) {
            JOptionPane.showMessageDialog(component, "This finding has no recoverable sourcesContent.")
            return
        }
        val dir = stageAll(d) ?: return
        launchEditor(dir)
    }

    private fun openSettings() {
        val message = "Editor command (executable or full path). The file or folder to open\n" +
            "is passed as an argument, so any editor works.\n\n" +
            "Examples:\n" +
            "  Linux/macOS: code   codium   subl   /usr/bin/code\n" +
            "  Windows:     code   code.cmd   \"C:\\\\Program Files\\\\...\\\\bin\\\\code.cmd\""
        val input = JOptionPane.showInputDialog(component, message, config.editorCommand) ?: return
        config.editorCommand = input.trim().ifBlank { "code" }
        settings.saveEditorCommand()
    }

    private fun stagingDir(d: Detection) =
        File(System.getProperty("java.io.tmpdir"), "map2pack/${d.index}")

    /** Writes a single source under the staging dir. Returns the file or null on error. */
    private fun stageFile(d: Detection, row: Int): File? {
        val content = sourcesModel.contentAt(row) ?: return null
        val file = File(stagingDir(d), SourceMapAnalyzer.sanitizeSourcePath(d.sources[row]))
        return try {
            file.parentFile?.mkdirs()
            file.writeText(content)
            file
        } catch (e: Exception) {
            api.logging().logToError("Error staging file for VS Code: ${e.message}")
            JOptionPane.showMessageDialog(component, "Error writing temp file: ${e.message}")
            null
        }
    }

    /** Writes every recoverable source under the staging dir. Returns the dir or null on error. */
    private fun stageAll(d: Detection): File? {
        val dir = stagingDir(d)
        return try {
            var written = 0
            for (i in d.sources.indices) {
                val content = d.sourcesContent.getOrNull(i)
                if (content.isNullOrEmpty()) continue
                val file = File(dir, SourceMapAnalyzer.sanitizeSourcePath(d.sources[i]))
                file.parentFile?.mkdirs()
                file.writeText(content)
                written++
            }
            api.logging().logToOutput("Staged $written files to ${dir.absolutePath}")
            dir
        } catch (e: Exception) {
            api.logging().logToError("Error staging sources: ${e.message}")
            JOptionPane.showMessageDialog(component, "Error staging files: ${e.message}")
            null
        }
    }

    /** Launches the configured editor off the EDT; the command may not exist on this machine. */
    private fun launchEditor(target: File) {
        val editor = config.editorCommand.trim().ifBlank { "code" }
        val onWindows = System.getProperty("os.name").lowercase().contains("win")
        // On Windows `code` resolves to code.cmd, which needs the shell.
        val cmd = if (onWindows) listOf("cmd", "/c", editor, target.absolutePath)
        else listOf(editor, target.absolutePath)
        Thread {
            try {
                ProcessBuilder(cmd).start()
            } catch (e: Exception) {
                api.logging().logToError("Could not launch editor '$editor': ${e.message}")
                SwingUtilities.invokeLater {
                    JOptionPane.showMessageDialog(
                        component,
                        "Could not launch editor '$editor'.\n" +
                            "Set the correct command in Settings...\n\n" +
                            "Staged at:\n${target.absolutePath}"
                    )
                }
            }
        }.start()
    }

    private fun copySelectedPath() {
        val d = current ?: return
        val row = selectedSourceRow().takeIf { it >= 0 } ?: return
        val selection = StringSelection(d.sources[row])
        Toolkit.getDefaultToolkit().systemClipboard.setContents(selection, null)
    }

    /** Recoverable findings selected in the table, or every recoverable one when nothing is selected. */
    private fun exportTargets(): List<Detection> {
        val selected = findingsTable.selectedRows
            .map { findingsTable.convertRowIndexToModel(it) }
            .mapNotNull { detections.getOrNull(it) }
        return (if (selected.isEmpty()) detections.toList() else selected).filter { it.recoverable }
    }

    private fun exportAll() {
        val targets = exportTargets()
        if (targets.isEmpty()) {
            JOptionPane.showMessageDialog(component, "No selected finding has recoverable sourcesContent.")
            return
        }
        val chooser = JFileChooser().apply {
            fileSelectionMode = JFileChooser.DIRECTORIES_ONLY
            dialogTitle = "Destination folder for recovered source"
        }
        if (chooser.showDialog(component, "Select") != JFileChooser.APPROVE_OPTION) return
        val dest = chooser.selectedFile ?: return

        var written = 0
        try {
            for (d in targets) {
                val safeHost = d.host.replace(Regex("[^A-Za-z0-9._-]"), "_")
                val baseDir = File(dest, "map2pack_${d.index}_$safeHost")
                for (i in d.sources.indices) {
                    val content = d.sourcesContent.getOrNull(i)
                    if (content.isNullOrEmpty()) continue
                    val outFile = File(baseDir, SourceMapAnalyzer.sanitizeSourcePath(d.sources[i]))
                    outFile.parentFile?.mkdirs()
                    outFile.writeText(content)
                    written++
                }
            }
            api.logging().logToOutput(
                "Exported $written files from ${targets.size} finding(s) to ${dest.absolutePath}"
            )
            val choice = JOptionPane.showConfirmDialog(
                component,
                "Exported $written files from ${targets.size} finding(s) to:\n${dest.absolutePath}\n\nOpen folder?",
                "Export complete",
                JOptionPane.YES_NO_OPTION
            )
            if (choice == JOptionPane.YES_OPTION) openFolder(dest)
        } catch (e: Exception) {
            api.logging().logToError("Error exporting to ${dest.absolutePath}: ${e.message}")
            JOptionPane.showMessageDialog(component, "Error exporting: ${e.message}")
        }
    }

    private fun openFolder(dir: File) {
        Thread {
            try {
                if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.OPEN)) {
                    Desktop.getDesktop().open(dir)
                } else {
                    ProcessBuilder("xdg-open", dir.absolutePath).start()
                }
            } catch (e: Exception) {
                try {
                    ProcessBuilder("xdg-open", dir.absolutePath).start()
                } catch (e2: Exception) {
                    api.logging().logToError("Could not open folder ${dir.absolutePath}: ${e2.message}")
                }
            }
        }.start()
    }

    // ---- helpers ----

    private fun severityLabel(severity: AuditIssueSeverity): String = when (severity) {
        AuditIssueSeverity.HIGH -> "HIGH"
        AuditIssueSeverity.MEDIUM -> "MEDIUM"
        AuditIssueSeverity.LOW -> "LOW"
        else -> "INFO"
    }

    private fun humanSize(n: Int): String = when {
        n < 1024 -> "$n b"
        n < 1024 * 1024 -> "%.1f k".format(n / 1024.0)
        else -> "%.1f M".format(n / (1024.0 * 1024))
    }

    private fun emptyBorder() = BorderFactory.createEmptyBorder(pad / 2, pad / 2, pad / 2, pad / 2)

    private fun caption(text: String) = JLabel("$text:").also { captionLabels.add(it) }

    private fun readOnlyField() = JTextField().apply {
        isEditable = false
        isOpaque = false
        border = null
    }

    private fun wrappedText() = JTextArea().apply {
        isEditable = false
        isOpaque = false
        lineWrap = true
        wrapStyleWord = true
        border = null
    }

    private fun gbc(x: Int, y: Int, width: Int = 1, weightx: Double = 0.0) = GridBagConstraints().apply {
        gridx = x
        gridy = y
        gridwidth = width
        this.weightx = weightx
        fill = GridBagConstraints.HORIZONTAL
        anchor = GridBagConstraints.WEST
        insets = Insets(pad / 4, pad / 3, pad / 4, pad / 3)
    }

    private fun setFindingsWidths() {
        val widths = intArrayOf(40, 80, 90, 140, 300, 280, 70, 100, 80, 120)
        for (i in widths.indices) {
            if (i < findingsTable.columnModel.columnCount) {
                findingsTable.columnModel.getColumn(i).preferredWidth = widths[i]
            }
        }
    }

    private inner class FindingsTableModel(
        private val rows: List<Detection>
    ) : AbstractTableModel() {
        private val cols = arrayOf(
            "#", "Time", "Severity", "Method", "JS URL", "Map URL",
            "Sources", "Recoverable", "Webpack", "Status"
        )

        override fun getRowCount(): Int = rows.size
        override fun getColumnCount(): Int = cols.size
        override fun getColumnName(column: Int): String = cols[column]

        override fun getColumnClass(columnIndex: Int): Class<*> = when (columnIndex) {
            0, 6, 7 -> Int::class.javaObjectType
            else -> String::class.java
        }

        override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
            val d = rows[rowIndex]
            return when (columnIndex) {
                0 -> d.index
                1 -> d.time
                2 -> severityLabel(d.severity)
                3 -> d.method.label
                4 -> d.jsUrl
                5 -> d.mapUrl ?: "-"
                6 -> d.sourceCount
                7 -> d.recoverableCount
                8 -> if (d.hasWebpack) "yes" else "-"
                9 -> d.status
                else -> ""
            }
        }
    }

    private inner class SourcesTableModel : AbstractTableModel() {
        private var sources: List<String> = emptyList()
        private var contents: List<String?> = emptyList()
        private val cols = arrayOf("File", "Size")

        fun setData(sources: List<String>, contents: List<String?>) {
            this.sources = sources
            this.contents = contents
            fireTableDataChanged()
        }

        fun contentAt(row: Int): String? = contents.getOrNull(row)

        override fun getRowCount(): Int = sources.size
        override fun getColumnCount(): Int = cols.size
        override fun getColumnName(column: Int): String = cols[column]

        override fun getValueAt(rowIndex: Int, columnIndex: Int): Any = when (columnIndex) {
            0 -> sources[rowIndex]
            else -> contents.getOrNull(rowIndex)?.let { humanSize(it.length) } ?: "-"
        }
    }
}
