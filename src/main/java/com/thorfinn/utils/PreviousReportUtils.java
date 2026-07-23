package com.thorfinn.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.thorfinn.models.Finding;
import com.thorfinn.models.VerificationResult;
import lombok.extern.slf4j.Slf4j;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;


@Slf4j
public final class PreviousReportUtils {

    private static JsonNode previousFindings;
    private static boolean diffMode;

    private PreviousReportUtils() {
    }

    public static void initialize(String reportPath, boolean diff) {
        previousFindings = null;
        diffMode = diff;
        if (reportPath == null || reportPath.isBlank()) {
            return;
        }
        Path path = Path.of(reportPath);
        if (!Files.isRegularFile(path)) {
            log.warn("[!] previous report not found, ignoring: {}", reportPath);
            return;
        }
        try {
            JsonNode root = new ObjectMapper().readTree(Files.readString(path));
            JsonNode findings = root.get("findings");
            if (findings == null || !findings.isArray()) {
                log.warn("[!] previous report has no 'findings' array, ignoring: {}", reportPath);
                return;
            }
            previousFindings = findings;
            log.info("[*] Loaded previous report for {}: {} ({} finding(s))",
                    diffMode ? "diff scan" : "verdict reuse", reportPath, findings.size());
        } catch (Exception e) {
            log.warn("[!] Failed to load previous report '{}', continuing without it: {}", reportPath, e.getMessage());
        }
    }

    public static boolean isDiffMode() {
        return diffMode && previousFindings != null;
    }

    public static Finding reuse(String tool, String sourceFile, String sinkFile, String rawFlow) {
        JsonNode f = match(tool, sourceFile, sinkFile, rawFlow);
        if (f == null) {
            return null;
        }
        String status = text(f, "status");
        if ("LLM ERROR".equalsIgnoreCase(status)) {
            return null;
        }
        boolean truePositive = "TRUE POSITIVE".equalsIgnoreCase(status);
        return Finding.builder()
                .tool(tool)
                .truePositive(truePositive)
                .carriedOver(diffMode)
                .version(text(f, "version"))
                .sourceFile(sourceFile)
                .sinkFile(sinkFile)
                .rawFlow(rawFlow)
                .vulnerabilityClass(text(f, "vulnerabilityClass"))
                .analysis(text(f, "llmVerdict"))
                .poc(truePositive ? text(f, "pocCommand") : null)
                .build();
    }

    public static VerificationResult reuseResult(Finding finding) {
        JsonNode f = match(finding.getTool(), finding.getSourceFile(), finding.getSinkFile(), finding.getRawFlow());
        if (f == null) {
            return null;
        }
        List<String> evidence = new ArrayList<>();
        JsonNode ev = f.get("evidence");
        if (ev != null && ev.isArray()) {
            for (JsonNode e : ev) {
                if (!e.isNull()) {
                    evidence.add(e.asText());
                }
            }
        }
        return VerificationResult.builder()
                .finding(finding)
                .truePositive(finding.isTruePositive())
                .status("CARRIED_OVER")
                .commandExecuted(text(f, "pocCommand"))
                .output(text(f, "output"))
                .evidence(evidence)
                .build();
    }

    private static JsonNode match(String tool, String sourceFile, String sinkFile, String rawFlow) {
        if (previousFindings == null) {
            return null;
        }
        String signature = FindingSignature.compute(tool, sourceFile, sinkFile, rawFlow);
        for (JsonNode f : previousFindings) {
            if (signature.equals(text(f, "signature"))) {
                return f;
            }
        }
        return null;
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return (v == null || v.isNull()) ? null : v.asText();
    }
}

