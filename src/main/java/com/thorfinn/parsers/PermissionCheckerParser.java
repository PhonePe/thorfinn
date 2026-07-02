package com.thorfinn.parsers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.thorfinn.models.PermissionCheckerResult;
import com.thorfinn.models.PermissionCheckerResult.PermissionFinding;
import com.thorfinn.utils.PathUtils;
import lombok.extern.slf4j.Slf4j;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

@Slf4j
public class PermissionCheckerParser implements Parsers<PermissionCheckerResult> {

    private static final String OUTPUT_FILE = "permission_checker_output.json";
    private static final ObjectMapper mapper = new ObjectMapper();

    @Override
    public PermissionCheckerResult parse() throws Exception {
        Path outputPath = Paths.get(PathUtils.getOutputPath(), OUTPUT_FILE);

        if (!Files.exists(outputPath)) {
            throw new RuntimeException("PermissionChecker output not found: " + outputPath.toAbsolutePath());
        }

        String json = Files.readString(outputPath);
        JsonNode root = mapper.readTree(json);

        String manifest = root.path("manifest").asText("");
        String packageName = root.path("package").asText("");
        int totalFindings = root.path("total_findings").asInt(0);

        List<PermissionFinding> findings = new ArrayList<>();
        JsonNode findingsNode = root.path("findings");
        if (findingsNode.isArray()) {
            for (JsonNode node : findingsNode) {
                findings.add(PermissionFinding.builder()
                        .check(node.path("check").asText(""))
                        .severity(node.path("severity").asText(""))
                        .title(node.path("title").asText(""))
                        .description(node.path("description").asText(""))
                        .affectedComponent(node.path("affected_component").asText(""))
                        .permission(node.path("permission").asText(""))
                        .recommendation(node.path("recommendation").asText(""))
                        .attackScenario(node.path("attack_scenario").asText(""))
                        .build());
            }
        }

        PermissionCheckerResult result = PermissionCheckerResult.builder()
                .manifest(manifest)
                .packageName(packageName)
                .totalFindings(totalFindings)
                .findings(findings)
                .build();

        log.info("[*] Parsed PermissionChecker output: {} finding(s)", findings.size());
        for (int i = 0; i < findings.size(); i++) {
            PermissionFinding f = findings.get(i);
            log.info("[*]   Finding {}: [{}] {} — {}", i + 1, f.getSeverity(), f.getCheck(), f.getTitle());
        }

        return result;
    }
}
