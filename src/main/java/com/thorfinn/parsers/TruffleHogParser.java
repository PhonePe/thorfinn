package com.thorfinn.parsers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.thorfinn.models.TruffleHogResult;
import com.thorfinn.models.TruffleHogResult.SecretFinding;
import com.thorfinn.utils.PathUtils;
import lombok.extern.slf4j.Slf4j;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

@Slf4j
public class TruffleHogParser implements Parsers<TruffleHogResult> {

    private static final String OUTPUT_FILE = "trufflehog_output.json";
    private static final ObjectMapper mapper = new ObjectMapper();

    @Override
    public TruffleHogResult parse() throws Exception {
        Path outputPath = Paths.get(PathUtils.getOutputPath(), OUTPUT_FILE);

        if (!Files.exists(outputPath)) {
            throw new RuntimeException("TruffleHog output not found: " + outputPath.toAbsolutePath());
        }

        String content = Files.readString(outputPath);
        List<SecretFinding> findings = new ArrayList<>();

        for (String line : content.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || !trimmed.startsWith("{")) continue;

            try {
                JsonNode node = mapper.readTree(trimmed);

                JsonNode fsNode = node.path("SourceMetadata").path("Data").path("Filesystem");
                String absoluteFilePath = fsNode.path("file").asText("");
                int lineNumber = fsNode.path("line").asInt(0);

                String relativePath = absoluteFilePath;
                if (absoluteFilePath.contains("decompiled_apks/")) {
                    relativePath = absoluteFilePath.substring(
                            absoluteFilePath.indexOf("decompiled_apks/") + "decompiled_apks/".length()
                    );
                }

                findings.add(SecretFinding.builder()
                        .filePath(relativePath)
                        .lineNumber(lineNumber)
                        .raw(node.path("Raw").asText(""))
                        .build());
            } catch (Exception e) {
                log.warn("[!] Failed to parse TruffleHog line: {}", e.getMessage());
            }
        }

        TruffleHogResult result = TruffleHogResult.builder()
                .totalFindings(findings.size())
                .findings(findings)
                .build();

        log.info("[*] Parsed TruffleHog output: {} secret(s) found", findings.size());
        for (int i = 0; i < findings.size(); i++) {
            SecretFinding f = findings.get(i);
            log.info("[*]   Secret {}: {} (line {}) - {}", i + 1, f.getFilePath(), f.getLineNumber(), f.getRaw());
        }

        return result;
    }
}
