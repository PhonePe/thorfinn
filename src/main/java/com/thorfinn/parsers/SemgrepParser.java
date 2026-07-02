package com.thorfinn.parsers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.thorfinn.models.SemgrepResult;
import com.thorfinn.models.SemgrepResult.SemgrepFinding;
import com.thorfinn.utils.PathUtils;
import lombok.extern.slf4j.Slf4j;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

@Slf4j
public class SemgrepParser implements Parsers<SemgrepResult> {

    private static final String OUTPUT_FILE = "semgrep_output.json";
    private static final ObjectMapper mapper = new ObjectMapper();

    @Override
    public SemgrepResult parse() throws Exception {
        Path outputPath = Paths.get(PathUtils.getOutputPath(), OUTPUT_FILE);

        if (!Files.exists(outputPath)) {
            throw new RuntimeException("Semgrep output not found: " + outputPath.toAbsolutePath());
        }

        String rawOutput = Files.readString(outputPath);
        String json = extractJson(rawOutput);
        if (json == null) {
            log.warn("[!] No JSON object found in semgrep output");
            return SemgrepResult.builder().totalFindings(0).findings(List.of()).build();
        }

        JsonNode root = mapper.readTree(json);

        List<SemgrepFinding> findings = new ArrayList<>();
        JsonNode resultsNode = root.path("results");

        if (resultsNode.isArray()) {
            for (JsonNode node : resultsNode) {
                String ruleId = node.path("check_id").asText("");
                String filePath = node.path("path").asText("");
                int line = node.path("start").path("line").asInt(0);
                String severity = node.path("extra").path("severity").asText("WARNING");
                String message = node.path("extra").path("message").asText("");

                String matchedCode = node.path("extra").path("lines").asText("");

                Map<String, String> metavars = new HashMap<>();
                JsonNode metavarsNode = node.path("extra").path("metavars");
                if (metavarsNode.isObject()) {
                    Iterator<String> fieldNames = metavarsNode.fieldNames();
                    while (fieldNames.hasNext()) {
                        String key = fieldNames.next();
                        String value = metavarsNode.path(key).path("abstract_content").asText("");
                        metavars.put(key, value);
                    }
                }

                findings.add(SemgrepFinding.builder()
                        .ruleId(ruleId)
                        .filePath(filePath)
                        .lineNumber(line)
                        .matchedCode(matchedCode)
                        .message(message)
                        .severity(severity)
                        .metavars(metavars)
                        .build());
            }
        }

        SemgrepResult result = SemgrepResult.builder()
                .totalFindings(findings.size())
                .findings(findings)
                .build();

        log.info("[*] Parsed Semgrep output: {} finding(s)", findings.size());
        for (int i = 0; i < findings.size(); i++) {
            SemgrepFinding f = findings.get(i);
            log.info("[*]   Finding {}: [{}] {} at {}:{}", i + 1, f.getRuleId(), f.getSeverity(), f.getFilePath(), f.getLineNumber());
        }

        return result;
    }

    private String extractJson(String rawOutput) {
        for (String line : rawOutput.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.startsWith("{")) {
                return trimmed;
            }
        }
        return null;
    }
}
