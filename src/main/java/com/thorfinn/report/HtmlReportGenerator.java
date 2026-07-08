package com.thorfinn.report;

import com.thorfinn.models.Finding;
import com.thorfinn.models.ManifestInfo;
import com.thorfinn.models.ManifestInfo.ExportedComponent;
import com.thorfinn.models.VerificationResult;
import com.thorfinn.utils.PathUtils;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Slf4j
public class HtmlReportGenerator {
    private static final String REPORT_DIR = PathUtils.getBaseDirectory();

    public void generateReport(List<VerificationResult> results, ManifestInfo manifestInfo) {
        StringBuilder html = new StringBuilder();
        html.append(buildHead());
        html.append("<body>\n");
        html.append(buildHeader(results));
        html.append(buildAppInfoSection(manifestInfo));
        html.append(buildSummaryCards(results));
        html.append(buildFindingsSection(results));
        html.append(buildFooter());
        html.append("</body>\n</html>");

        String reportPath = Paths.get(REPORT_DIR, "thorfinn_report.html").toString();
        try {
            Path path = Path.of(reportPath);
            Files.createDirectories(path.getParent());
            Files.writeString(path, html.toString());
            log.info("[*] HTML report generated: {}", path.toAbsolutePath());
        } catch (IOException e) {
            log.error("[!] Failed to write HTML report: {}", e.getMessage());
        }
    }

    private String buildHead() {
        return """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Thorfinn - Security Analysis Report</title>
                <style>
                    @import url('https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;700;900&family=Libre+Baskerville:wght@400;700&family=IBM+Plex+Mono:wght@400;600&display=swap');

                    :root {
                        --bg-primary: #faf8f5;
                        --bg-secondary: #f3f0eb;
                        --bg-card: #ffffff;
                        --border: #2c2c2c;
                        --border-soft: #d4d0c8;
                        --text-primary: #1a1a1a;
                        --text-secondary: #4a4a4a;
                        --accent-green: #2d6a4f;
                        --accent-red: #8b1a1a;
                        --accent-yellow: #7a5c00;
                        --accent-blue: #1a3a5c;
                        --accent-purple: #3d2b56;
                        --accent-orange: #6b3a0a;
                        --heading-color: #1a1a1a;
                    }
                    * { margin: 0; padding: 0; box-sizing: border-box; }
                    body {
                        font-family: 'Libre Baskerville', 'Georgia', serif;
                        background: var(--bg-primary);
                        color: var(--text-primary);
                        line-height: 1.7;
                        padding: 2rem;
                    }
                    .container {
                        max-width: 1200px;
                        margin: 0 auto;
                        border: 1px solid var(--border);
                        border-radius: 0;
                        background: var(--bg-card);
                        box-shadow: 0 1px 4px rgba(0, 0, 0, 0.06);
                        padding: 2.5rem 3rem 2rem;
                        position: relative;
                    }
                    .container::before { content: none; }
                    .container::after { content: none; }
                    .header {
                        text-align: center;
                        padding: 0 0 1rem;
                        border-bottom: 3px double var(--border);
                        margin-bottom: 2rem;
                        position: relative;
                    }
                    .masthead-top {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        font-family: 'Libre Baskerville', serif;
                        font-size: 0.7rem;
                        text-transform: uppercase;
                        letter-spacing: 0.12em;
                        color: var(--text-secondary);
                        border-top: 1px solid var(--border);
                        border-bottom: 1px solid var(--border);
                        padding: 0.3rem 0;
                        margin-bottom: 1.2rem;
                    }
                    .header h1 {
                        font-family: 'Playfair Display', 'Georgia', serif;
                        font-size: 4rem;
                        font-weight: 900;
                        letter-spacing: 0.04em;
                        color: var(--heading-color);
                        margin-bottom: 0.5rem;
                        text-transform: uppercase;
                        line-height: 1.05;
                    }
                    .header .subtitle {
                        color: var(--text-primary);
                        font-size: 0.85rem;
                        letter-spacing: 0.05em;
                        font-style: italic;
                        border-top: 1px solid var(--border);
                        border-bottom: 1px solid var(--border);
                        display: inline-block;
                        padding: 0.3rem 1.5rem;
                        margin-top: 0.5rem;
                    }
                    .summary-grid {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                        gap: 0;
                        margin-bottom: 2rem;
                        border-top: 3px double var(--border);
                        border-bottom: 3px double var(--border);
                        padding: 1.2rem 0;
                    }
                    .summary-card {
                        background: transparent;
                        border: none;
                        border-right: 1px solid var(--border-soft);
                        border-radius: 0;
                        padding: 0.6rem 1rem;
                        text-align: center;
                    }
                    .summary-card:last-child { border-right: none; }
                    .summary-card::after { content: none; }
                    .summary-card .value {
                        font-family: 'Playfair Display', serif;
                        font-size: 2.6rem;
                        font-weight: 900;
                        margin-bottom: 0.2rem;
                        line-height: 1;
                    }
                    .summary-card .label {
                        color: var(--text-secondary);
                        font-size: 0.7rem;
                        text-transform: uppercase;
                        letter-spacing: 0.1em;
                        font-family: 'Libre Baskerville', serif;
                    }
                    .value.green { color: var(--accent-green); }
                    .value.red { color: var(--accent-red); }
                    .value.yellow { color: var(--accent-yellow); }
                    .value.blue { color: var(--accent-blue); }
                    .section-title {
                        font-family: 'Playfair Display', 'Georgia', serif;
                        font-size: 1.6rem;
                        font-weight: 900;
                        margin: 2.5rem 0 1rem;
                        padding-bottom: 0.4rem;
                        border-bottom: 3px double var(--border);
                        letter-spacing: 0.02em;
                        color: var(--heading-color);
                        text-transform: uppercase;
                        text-align: center;
                    }
                    table {
                        width: 100%;
                        table-layout: auto;
                        border-collapse: collapse;
                        margin-bottom: 2rem;
                        background: var(--bg-card);
                        border: 1px solid var(--border);
                        font-size: 0.85rem;
                    }
                    table th:first-child, table td:first-child {
                        width: 2rem;
                        text-align: center;
                    }
                    .finding-detail table th:first-child, .finding-detail table td:first-child {
                        width: auto;
                        text-align: left;
                    }
                    th {
                        background: var(--bg-secondary);
                        padding: 0.6rem 0.8rem;
                        text-align: left;
                        font-size: 0.72rem;
                        text-transform: uppercase;
                        letter-spacing: 0.06em;
                        color: var(--text-secondary);
                        border-bottom: 2px solid var(--border);
                        border-right: 1px solid var(--border-soft);
                        font-family: 'Libre Baskerville', serif;
                        font-weight: 700;
                        word-break: break-word;
                        overflow-wrap: anywhere;
                    }
                    th:last-child { border-right: none; }
                    td {
                        padding: 0.6rem 0.8rem;
                        border-bottom: 1px solid var(--border-soft);
                        border-right: 1px solid var(--border-soft);
                        font-size: 0.82rem;
                        vertical-align: top;
                        word-break: break-word;
                        overflow-wrap: anywhere;
                        white-space: normal;
                    }
                    td:last-child { border-right: none; }
                    td code {
                        word-break: break-all;
                        overflow-wrap: anywhere;
                        white-space: pre-wrap;
                    }
                    tr:last-child td { border-bottom: none; }
                    tr:hover td {
                        background: var(--bg-secondary);
                    }
                    tr.row-false-positive .badge,
                    tr.row-false-positive .vuln-tag {
                        background: #e8f5e9;
                        color: var(--accent-green);
                        border: 1px solid var(--accent-green);
                    }
                    tr.row-true-positive .badge,
                    tr.row-true-positive .vuln-tag {
                        background: #fde8e8;
                        color: var(--accent-red);
                        border: 1px solid var(--accent-red);
                    }
                    .badge {
                        display: inline-block;
                        padding: 0.15rem 0.5rem;
                        border-radius: 0;
                        font-size: 0.7rem;
                        font-weight: 700;
                        font-family: 'IBM Plex Mono', monospace;
                        text-transform: uppercase;
                        letter-spacing: 0.03em;
                    }
                    .badge-verified { background: #fde8e8; color: var(--accent-red); border: 1px solid var(--accent-red); }
                    .badge-error { background: #fff8e1; color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }
                    .badge-skipped { background: #fff8e1; color: var(--accent-yellow); border: 1px solid #c9a800; }
                    .badge-fp { background: #e8f5e9; color: var(--accent-green); border: 1px solid var(--accent-green); }
                    .finding-detail {
                        background: var(--bg-card);
                        border: none;
                        border-top: 2px solid var(--border);
                        border-bottom: 1px solid var(--border-soft);
                        padding: 1.2rem 0.5rem 1.5rem;
                        margin-bottom: 1.5rem;
                    }
                    .finding-detail h3 {
                        font-family: 'Playfair Display', serif;
                        font-size: 1.15rem;
                        font-weight: 700;
                        margin-bottom: 1rem;
                        display: flex;
                        align-items: center;
                        flex-wrap: wrap;
                        gap: 0.6rem;
                        color: var(--text-primary);
                        word-break: break-word;
                        overflow-wrap: anywhere;
                    }
                    .finding-detail h3 .finding-num {
                        background: var(--border);
                        color: var(--bg-card);
                        width: 26px;
                        height: 26px;
                        border-radius: 50%;
                        display: inline-flex;
                        align-items: center;
                        justify-content: center;
                        font-size: 0.75rem;
                        font-weight: 700;
                        flex-shrink: 0;
                        font-family: 'IBM Plex Mono', monospace;
                    }
                    .detail-grid {
                        display: grid;
                        grid-template-columns: 1fr 1fr;
                        gap: 0.8rem;
                        margin-bottom: 1rem;
                    }
                    .detail-item label {
                        display: block;
                        font-size: 0.68rem;
                        text-transform: uppercase;
                        letter-spacing: 0.06em;
                        color: var(--text-secondary);
                        margin-bottom: 0.2rem;
                        font-weight: 700;
                    }
                    .detail-item span {
                        font-size: 0.85rem;
                        word-break: break-word;
                        overflow-wrap: anywhere;
                    }
                    .code-block {
                        background: var(--bg-secondary);
                        border: 1px solid var(--border-soft);
                        padding: 1rem;
                        font-family: 'IBM Plex Mono', monospace;
                        font-size: 0.78rem;
                        overflow-x: auto;
                        white-space: pre-wrap;
                        word-break: break-all;
                        margin-top: 0.5rem;
                        max-height: 400px;
                        overflow-y: auto;
                        line-height: 1.5;
                        color: var(--text-primary);
                    }
                    .collapsible-header {
                        cursor: pointer;
                        display: flex;
                        align-items: center;
                        gap: 0.4rem;
                        padding: 0.4rem 0;
                        font-size: 0.82rem;
                        font-weight: 700;
                        color: var(--text-primary);
                        user-select: none;
                        text-transform: uppercase;
                        letter-spacing: 0.03em;
                    }
                    .collapsible-header:hover { text-decoration: underline; }
                    .collapsible-header .arrow { transition: transform 0.2s; display: inline-block; }
                    .collapsible-content { display: none; }
                    .collapsible-content.open { display: block; }
                    .vuln-tag {
                        display: inline-block;
                        padding: 0.12rem 0.45rem;
                        border-radius: 0;
                        font-size: 0.7rem;
                        font-weight: 700;
                        font-family: 'IBM Plex Mono', monospace;
                        text-transform: uppercase;
                        background: var(--bg-secondary);
                        color: var(--text-primary);
                        border: 1px solid var(--border);
                    }
                    .vuln-tag.vuln-tag-na {
                        background: #e8f5e9;
                        color: var(--accent-green);
                        border: 1px solid var(--accent-green);
                    }
                    .vuln-tag.vuln-tag-fp {
                        background: #e8f5e9;
                        color: var(--accent-green);
                        border: 1px solid var(--accent-green);
                    }
                    .vuln-tag.vuln-tag-tp {
                        background: #fde8e8;
                        color: var(--accent-red);
                        border: 1px solid var(--accent-red);
                    }
                    .status-icon {
                        font-weight: 700;
                        -webkit-text-fill-color: initial;
                    }
                    .status-icon.status-fp,
                    .status-icon.status-cross,
                    .status-icon.status-cross-emoji {
                        color: var(--accent-green) !important;
                    }
                    .status-icon.status-tp,
                    .status-icon.status-tick,
                    .status-icon.status-tick-emoji {
                        color: var(--accent-red) !important;
                    }
                    .flow-arrow { color: var(--text-secondary); font-weight: bold; margin: 0 0.4rem; }
                    .footer {
                        text-align: center;
                        padding: 1.5rem 0 1rem;
                        border-top: 2px solid var(--border);
                        margin-top: 2rem;
                        color: var(--text-secondary);
                        font-size: 0.75rem;
                        font-style: italic;
                    }
                    @media (max-width: 768px) {
                        .detail-grid { grid-template-columns: 1fr; }
                        body { padding: 1rem; }
                    }
                </style>
                <script>
                function toggleCollapsible(id) {
                    var el = document.getElementById(id);
                    var arrow = document.getElementById('arrow-' + id);
                    if (el.classList.contains('open')) {
                        el.classList.remove('open');
                        arrow.style.transform = 'rotate(0deg)';
                    } else {
                        el.classList.add('open');
                        arrow.style.transform = 'rotate(90deg)';
                    }
                }

                document.addEventListener('DOMContentLoaded', function() {
                    var tables = document.querySelectorAll('table');
                    tables.forEach(function(table) {
                        var headers = table.querySelectorAll('thead th');
                        var isIssueTable = Array.from(headers).some(function(th) {
                            return th.textContent && th.textContent.trim().toUpperCase() === 'VERDICT';
                        });
                        if (!isIssueTable) return;

                        var rows = table.querySelectorAll('tbody tr');
                        rows.forEach(function(row) {
                            var verdictBadge = row.querySelector('td .badge');
                            if (!verdictBadge || !verdictBadge.textContent) return;

                            var verdict = verdictBadge.textContent.trim().toUpperCase();
                            if (verdict === 'FALSE POSITIVE') {
                                row.classList.add('row-false-positive');
                                row.classList.remove('row-true-positive');
                            } else if (verdict === 'TRUE POSITIVE') {
                                row.classList.add('row-true-positive');
                                row.classList.remove('row-false-positive');
                            }
                        });
                    });

                    var iconHosts = document.querySelectorAll('.finding-detail h3, table td, table th, .detail-item span');
                    iconHosts.forEach(function(host) {
                        if (host.innerHTML.includes('✅')) {
                            host.innerHTML = host.innerHTML.replace(/✅/g, '<span class="status-icon status-tick-emoji">✔</span>');
                        }
                        if (host.innerHTML.includes('❌')) {
                            host.innerHTML = host.innerHTML.replace(/❌/g, '<span class="status-icon status-cross-emoji">✖</span>');
                        }
                    });

                    var vulnTags = document.querySelectorAll('.vuln-tag');
                    vulnTags.forEach(function(tag) {
                        if (tag.textContent && tag.textContent.trim().toUpperCase() === 'N/A') {
                            tag.classList.add('vuln-tag-na');
                        }
                    });

                    var detailItems = document.querySelectorAll('.finding-detail .detail-item');
                    detailItems.forEach(function(item) {
                        var label = item.querySelector('label');
                        var value = item.querySelector('span');
                        if (!label || !value) return;
                        if (label.textContent.trim().toUpperCase() !== 'VERDICT') return;
                        if (value.querySelector('.badge')) return;

                        var verdictText = value.textContent ? value.textContent.trim().toUpperCase() : '';
                        if (verdictText === 'TRUE POSITIVE') {
                            value.innerHTML = '<span class="badge badge-verified">TRUE POSITIVE</span>';
                        } else if (verdictText === 'FALSE POSITIVE') {
                            value.innerHTML = '<span class="badge badge-fp">FALSE POSITIVE</span>';
                        }
                    });

                    var findingDetails = document.querySelectorAll('.finding-detail');
                    findingDetails.forEach(function(card) {
                        var verdictLabel = null;
                        var labels = card.querySelectorAll('.detail-item label');
                        labels.forEach(function(lbl) {
                            if (lbl.textContent && lbl.textContent.trim().toUpperCase() === 'VERDICT') {
                                verdictLabel = lbl;
                            }
                        });
                        if (!verdictLabel) return;

                        var verdictValue = verdictLabel.parentElement.querySelector('span');
                        if (!verdictValue || !verdictValue.textContent) return;

                        var verdictText = verdictValue.textContent.trim().toUpperCase();
                        var tag = card.querySelector('h3 .vuln-tag');
                        if (!tag) return;

                        tag.classList.remove('vuln-tag-fp', 'vuln-tag-tp');
                        if (verdictText === 'FALSE POSITIVE') {
                            tag.classList.add('vuln-tag-fp');
                        } else if (verdictText === 'TRUE POSITIVE') {
                            tag.classList.add('vuln-tag-tp');
                        }
                    });
                });
                </script>
                </head>
                """;
    }

    private String buildHeader(List<VerificationResult> results) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        String dateLine = LocalDateTime.now().format(DateTimeFormatter.ofPattern("EEEE, MMMM d, yyyy"));
        return """
                <div class="container">
                <div class="header">
                    <div class="masthead-top">
                        <span>%s</span>
                        <span>Confidential</span>
                    </div>
                    <h1>Thorfinn</h1>
                    <p class="subtitle">Android Security Analysis Report - Generated %s</p>
                </div>
                """.formatted(escapeHtml(dateLine), escapeHtml(timestamp));
    }

    private String buildAppInfoSection(ManifestInfo info) {
        if (info == null) return "";

        StringBuilder sb = new StringBuilder();
        sb.append("<h2 class=\"section-title\">📱 Application Info</h2>\n");

        sb.append("<div class=\"finding-detail\">\n");
        sb.append("<div class=\"detail-grid\">\n");
        sb.append(detailItem("Package Name", nullSafe(info.getPackageName())));
        sb.append(detailItem("Version", nullSafe(info.getVersionName()) + " (" + nullSafe(info.getVersionCode()) + ")"));
        sb.append(detailItem("Min SDK", nullSafe(info.getMinSdkVersion())));
        sb.append(detailItem("Target SDK", nullSafe(info.getTargetSdkVersion())));
        sb.append(detailItem("Debuggable", info.isDebuggable() ? "⚠️ YES" : "No"));
        sb.append(detailItem("Allow Backup", info.isAllowBackup() ? "⚠️ YES" : "No"));
        sb.append(detailItem("Cleartext Traffic", info.isUsesCleartextTraffic() ? "⚠️ YES" : "No"));
        sb.append("</div>\n");

        if (info.getPermissions() != null && !info.getPermissions().isEmpty()) {
            StringBuilder permContent = new StringBuilder();
            for (String perm : info.getPermissions()) {
                permContent.append(perm).append("\n");
            }
            sb.append(collapsibleSection("app-permissions", "🔑 Permissions (" + info.getPermissions().size() + ")", permContent.toString(), true));
        }

        sb.append(buildExportedComponentTable("Exported Activities", "exported-activities", info.getExportedActivities()));
        sb.append(buildExportedComponentTable("Exported Services", "exported-services", info.getExportedServices()));
        sb.append(buildExportedComponentTable("Exported Receivers", "exported-receivers", info.getExportedReceivers()));
        sb.append(buildExportedComponentTable("Exported Providers", "exported-providers", info.getExportedProviders()));

        sb.append("</div>\n");
        return sb.toString();
    }

    private String buildExportedComponentTable(String title, String id, List<ExportedComponent> components) {
        if (components == null || components.isEmpty()) return "";

        StringBuilder content = new StringBuilder();
        content.append("<table style=\"margin-top:0.5rem\">\n<thead><tr>");
        content.append("<th>Component</th><th>Required Permission</th><th>Intent Filters</th>");
        content.append("</tr></thead>\n<tbody>\n");

        for (ExportedComponent c : components) {
            content.append("<tr>");
            content.append("<td>").append(escapeHtml(c.getName())).append("</td>");
            content.append("<td>").append(c.getPermission() != null ? "<span class=\"badge badge-skipped\">" + escapeHtml(c.getPermission()) + "</span>" : "<span class=\"badge badge-error\">None</span>").append("</td>");
            content.append("<td>");
            if (c.getIntentFilters() != null && !c.getIntentFilters().isEmpty()) {
                for (String filter : c.getIntentFilters()) {
                    content.append("<div style=\"font-size:0.8rem;color:var(--text-secondary)\">").append(escapeHtml(filter)).append("</div>");
                }
            } else {
                content.append("<span style=\"color:var(--text-secondary)\">-</span>");
            }
            content.append("</td>");
            content.append("</tr>\n");
        }

        content.append("</tbody>\n</table>\n");

        return """
                <div class="collapsible-header" onclick="toggleCollapsible('%s')">
                    <span class="arrow" id="arrow-%s" style="transform:rotate(90deg)">▶</span> %s (%d)
                </div>
                <div class="collapsible-content open" id="%s">
                    %s
                </div>
                """.formatted(id, id, escapeHtml(title), components.size(), id, content.toString());
    }

    private String buildSummaryCards(List<VerificationResult> results) {
        long truePositives = results.stream().filter(VerificationResult::isTruePositive).count();
        long falsePositives = results.stream().filter(r -> !r.isTruePositive()).count();
        long executed = results.stream().filter(r -> "EXECUTED".equals(r.getStatus())).count();
        long errors = results.stream().filter(r -> "ERROR".equals(r.getStatus())).count();
        long totalFindings = results.size();

        return """
                <div class="summary-grid">
                    <div class="summary-card">
                        <div class="value blue">%d</div>
                        <div class="label">Total Findings</div>
                    </div>
                    <div class="summary-card">
                        <div class="value green">%d</div>
                        <div class="label">True Positives</div>
                    </div>
                    <div class="summary-card">
                        <div class="value yellow">%d</div>
                        <div class="label">False Positives</div>
                    </div>
                    <div class="summary-card">
                        <div class="value green">%d</div>
                        <div class="label">POCs Executed</div>
                    </div>
                    <div class="summary-card">
                        <div class="value red">%d</div>
                        <div class="label">Errors</div>
                    </div>
                </div>
                """.formatted(totalFindings, truePositives, falsePositives, executed, errors);
    }

    private String buildFindingsSection(List<VerificationResult> results) {
        if (results.isEmpty()) return "";

        StringBuilder sb = new StringBuilder();
        sb.append("<h2 class=\"section-title\">🔍 Security Findings</h2>\n");

        sb.append("<table>\n<thead><tr>");
        sb.append("<th>#</th><th>Verdict</th><th>Vulnerability</th><th>Source</th><th>Sink</th><th>Status</th><th>Evidence</th>");
        sb.append("</tr></thead>\n<tbody>\n");

        for (int i = 0; i < results.size(); i++) {
            VerificationResult r = results.get(i);
            Finding f = r.getFinding();
            String badgeClass = statusBadgeClass(r.getStatus());
            String verdictBadge = verdictBadge(r.isTruePositive());
            String rowClass = r.isTruePositive() ? " class=\"row-true-positive\"" : "";
            int evidenceCount = r.getEvidence() != null ? r.getEvidence().size() : 0;

            String source = getDisplaySource(f);
            String sink = getDisplaySink(f);

            sb.append("<tr").append(rowClass).append(">");
            sb.append("<td>").append(i + 1).append("</td>");
            sb.append("<td>").append(verdictBadge).append("</td>");
            sb.append("<td><span class=\"vuln-tag\">").append(escapeHtml(nullSafe(f.getVulnerabilityClass()))).append("</span></td>");
            sb.append("<td>").append(escapeHtml(source)).append("</td>");
            sb.append("<td>").append(escapeHtml(sink)).append("</td>");
            sb.append("<td><span class=\"badge ").append(badgeClass).append("\">").append(escapeHtml(r.getStatus())).append("</span></td>");
            sb.append("<td>").append(evidenceCount).append("</td>");
            sb.append("</tr>\n");
        }
        sb.append("</tbody>\n</table>\n");

        for (int i = 0; i < results.size(); i++) {
            VerificationResult r = results.get(i);
            Finding f = r.getFinding();
            String idx = f.getTool() + "-" + (i + 1);

            String source = getDisplaySource(f);
            String sink = getDisplaySink(f);

            sb.append("<div class=\"finding-detail\">\n");

            String verdictLabel = r.isTruePositive() ? "✅" : "❌";
            sb.append("<h3><span class=\"finding-num\">").append(i + 1).append("</span> ");
            sb.append(verdictLabel).append(" ");
            sb.append("<span class=\"vuln-tag\">").append(escapeHtml(nullSafe(f.getVulnerabilityClass()))).append("</span> ");
            sb.append(escapeHtml(source));
            if (!"N/A".equals(sink)) {
                sb.append(" <span class=\"flow-arrow\">→</span> ").append(escapeHtml(sink));
            }
            sb.append("</h3>\n");

            sb.append("<div class=\"detail-grid\">\n");
            sb.append(detailItem("Verdict", r.isTruePositive() ? "True Positive" : "False Positive"));
            sb.append(detailItem("Tool", getToolDisplayName(f.getTool())));
            sb.append(detailItem("Source", source));
            sb.append(detailItem("Sink", sink));
            sb.append(detailItem("Vulnerability Class", nullSafe(f.getVulnerabilityClass())));
            sb.append(detailItem("Status", r.getStatus()));
            sb.append("</div>\n");

            if (f.getRawFlow() != null && !f.getRawFlow().isBlank()) {
                String flowLabel = "truffleHog".equals(f.getTool()) ? "🔒 Secret Value" : "Taint Flow";
                sb.append(collapsibleSection("flow-" + idx, flowLabel, f.getRawFlow()));
            }
            appendCommonSections(sb, r, f, idx);

            sb.append("</div>\n");
        }

        return sb.toString();
    }

    private String getDisplaySource(Finding f) {
        if (f.getSourceFile() == null || f.getSourceFile().isBlank()) return "N/A";
        return toRelativePath(f.getSourceFile());
    }

    private String getDisplaySink(Finding f) {
        String tool = f.getTool();
        if ("permissionChecker".equals(tool) || "truffleHog".equals(tool)) {
            return "N/A";
        }
        if (f.getSinkFile() == null || f.getSinkFile().isBlank()) return "N/A";
        return toRelativePath(f.getSinkFile());
    }

    private String getToolDisplayName(String tool) {
        if (tool == null) return "Unknown";
        return switch (tool) {
            case "taie" -> "TaiE";
            case "permissionChecker" -> "PermissionChecker";
            case "truffleHog" -> "TruffleHog";
            case "semgrep" -> "Semgrep";
            default -> tool;
        };
    }

    private void appendCommonSections(StringBuilder sb, VerificationResult r, Finding f, String idx) {
        if (f.getAnalysis() != null && !f.getAnalysis().isBlank()) {
            sb.append(collapsibleSection("analysis-" + idx, "LLM Analysis", f.getAnalysis()));
        }
        if (f.getPoc() != null && !f.getPoc().isBlank()) {
            sb.append(collapsibleSection("poc-" + idx, "Proof of Concept", f.getPoc()));
        }
        if (r.getOutput() != null && !r.getOutput().isBlank()) {
            sb.append(collapsibleSection("output-" + idx, "Command Output", r.getOutput()));
        }
        if (r.getEvidence() != null && !r.getEvidence().isEmpty()) {
            StringBuilder evidenceContent = new StringBuilder();
            evidenceContent.append("Total evidence collected: ").append(r.getEvidence().size()).append("\n\n");
            for (int j = 0; j < r.getEvidence().size(); j++) {
                evidenceContent.append(j + 1).append(". ").append(r.getEvidence().get(j)).append("\n");
            }
            sb.append(collapsibleSection("evidence-" + idx, "🔍 Evidence (" + r.getEvidence().size() + ")", evidenceContent.toString()));
        }
        if (r.getErrorMessage() != null && !r.getErrorMessage().isBlank()) {
            sb.append(collapsibleSection("error-" + idx, "Error Details", r.getErrorMessage()));
        }
    }

    private String statusBadgeClass(String status) {
        return switch (status) {
            case "EXECUTED" -> "badge-verified";
            case "ERROR" -> "badge-error";
            case "FALSE_POSITIVE" -> "badge-fp";
            case "EXECUTED_NO_EVIDENCE" -> "badge-skipped";
            default -> "badge-skipped";
        };
    }

    private String verdictBadge(boolean truePositive) {
        return truePositive
                ? "<span class=\"badge badge-verified\">TRUE POSITIVE</span>"
                : "<span class=\"badge badge-fp\">FALSE POSITIVE</span>";
    }

    private String collapsibleSection(String id, String title, String content) {
        return collapsibleSection(id, title, content, false);
    }

    private String collapsibleSection(String id, String title, String content, boolean openByDefault) {
        String openClass = openByDefault ? " open" : "";
        String arrowStyle = openByDefault ? " style=\"transform:rotate(90deg)\"" : "";
        return """
                <div class="collapsible-header" onclick="toggleCollapsible('%s')">
                    <span class="arrow" id="arrow-%s"%s>▶</span> %s
                </div>
                <div class="collapsible-content%s" id="%s">
                    <div class="code-block">%s</div>
                </div>
                """.formatted(id, id, arrowStyle, escapeHtml(title), openClass, id, escapeHtml(content));
    }

    private String detailItem(String label, String value) {
        return """
                <div class="detail-item">
                    <label>%s</label>
                    <span>%s</span>
                </div>
                """.formatted(escapeHtml(label), escapeHtml(value));
    }

    private String buildFooter() {
        return """
                <div class="footer">
                    Thorfinn - Android Security Analysis Framework<br>
                    Report generated automatically. Verify each finding manually before reporting.
                </div>
                </div>
                """;
    }

    private String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private String nullSafe(String value) {
        return (value == null || value.isBlank()) ? "N/A" : value;
    }

    private String toRelativePath(String absolutePath) {
        if (absolutePath == null) return "N/A";
        int idx = absolutePath.indexOf("decompiled_apks/");
        if (idx != -1) {
            return absolutePath.substring(idx + "decompiled_apks/".length());
        }
        idx = absolutePath.indexOf("sources/");
        if (idx != -1) {
            return absolutePath.substring(idx);
        }
        return absolutePath;
    }
}
