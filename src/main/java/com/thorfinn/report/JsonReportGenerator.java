package com.thorfinn.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.thorfinn.models.Finding;
import com.thorfinn.models.ManifestInfo;
import com.thorfinn.models.VerificationResult;
import com.thorfinn.utils.PathUtils;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Slf4j
public class JsonReportGenerator {
    private static final String REPORT_DIR = PathUtils.getBaseDirectory();

    private final ObjectMapper mapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    public void generateReport(List<VerificationResult> results, ManifestInfo manifestInfo) {
        List<Map<String, Object>> vulnerabilities = new ArrayList<>();
        for (VerificationResult r : results) {
            if (!r.isTruePositive()) continue;
            Finding f = r.getFinding();

            Map<String, Object> vuln = new LinkedHashMap<>();
            vuln.put("source", toRelativePath(f.getSourceFile()));
            vuln.put("sink", getDisplaySink(f));
            vuln.put("taintFlow", f.getRawFlow());
            vuln.put("llmVerdict", f.getAnalysis());
            vuln.put("pocCommand", r.getCommandExecuted());
            vuln.put("output", r.getOutput());
            vuln.put("evidence", r.getEvidence() != null ? r.getEvidence() : List.of());
            vulnerabilities.add(vuln);
        }

        String reportPath = Paths.get(REPORT_DIR, "thorfinn_report.json").toString();
        try {
            Path path = Path.of(reportPath);
            Files.createDirectories(path.getParent());
            Files.writeString(path, mapper.writeValueAsString(vulnerabilities));
            log.info("[*] JSON report generated: {}", path.toAbsolutePath());
        } catch (IOException e) {
            log.error("[!] Failed to write JSON report: {}", e.getMessage());
        }
    }

    private String getDisplaySink(Finding f) {
        String tool = f.getTool();
        if ("permissionChecker".equals(tool) || "truffleHog".equals(tool)) {
            return null;
        }
        return toRelativePath(f.getSinkFile());
    }

    private String toRelativePath(String absolutePath) {
        if (absolutePath == null || absolutePath.isBlank()) return null;
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

