package com.thorfinn.poc;

import com.thorfinn.config.ConfigContext;
import com.thorfinn.config.ToolsConfig;
import com.thorfinn.models.Finding;
import com.thorfinn.models.PermissionCheckerResult;
import com.thorfinn.models.PermissionCheckerResult.PermissionFinding;
import com.thorfinn.parsers.PermissionCheckerParser;
import com.thorfinn.utils.LLMClient;
import com.thorfinn.utils.PathUtils;
import lombok.extern.slf4j.Slf4j;

import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

@Slf4j
public class PermissionCheckerPOC implements poc {

    private static final String SYSTEM_PROMPT = """
            You are an expert Android security researcher specializing in permission misconfigurations.
            
            You will be given a finding from a static analysis tool that detected a permission issue in an Android manifest.
            The finding includes the check type, severity, description, affected component, permission name,
            recommendation, and a potential attack scenario.
            
            You will also be given the full AndroidManifest.xml for context.
            
            YOUR JOB:
            1. Analyze if this finding is a TRUE POSITIVE or FALSE POSITIVE.
               - Consider if the affected component is actually exported and reachable by a third-party app.
               - Consider if the permission issue actually leads to unauthorized access to the component.
               - Consider if the component handles sensitive data or performs privileged actions (check the manifest for intent-filters, authorities, data schemes, etc.).
               - A finding is TRUE POSITIVE if a malicious app can exploit the permission misconfiguration to access a component it shouldn't be able to.
               - A finding is FALSE POSITIVE if the component is not exported, or the permission issue has no real security impact.
            
            2. If TRUE POSITIVE, explain the exploitation scenario in detail.
            
            IMPORTANT: These permission issues are NOT exploitable via adb commands. They require a malicious
            attacker app installed on the same device. Your POC must describe the attacker app approach.
            
            RESPONSE FORMAT:
            
            === VERDICT ===
            TRUE_POSITIVE or FALSE_POSITIVE
            
            === VULNERABILITY CLASS ===
            (One of: Missing protectionLevel, Permission Name Typo, Component Attribute Typo, Ecosystem Permission Issue, Provider Permission Gap. If FALSE_POSITIVE, write "N/A")
            
            === ANALYSIS ===
            (Your detailed reasoning for THIS specific finding. Explain what the permission issue is, which component is affected, and why it is or isn't exploitable.)
            
            === POC ===
            (If FALSE_POSITIVE, write "N/A")
            (If TRUE_POSITIVE, you MUST provide ALL of the following:)
            
            1. EXPLOITATION SUMMARY: A clear step-by-step explanation of how a malicious app exploits this issue.
            
            2. ATTACKER APP MANIFEST: The AndroidManifest.xml snippet for the attacker app, showing:
               - The <uses-permission> declaration to obtain the vulnerable permission
               - OR the <permission> declaration if the attacker is hijacking/registering the permission
               - Any required components in the attacker app
            
            3. ATTACKER APP CODE: Java/Kotlin code showing how the attacker app accesses the vulnerable component:
               - For Activities: Intent construction and startActivity() call
               - For Services: Intent construction and startService()/bindService() call
               - For BroadcastReceivers: Intent construction and sendBroadcast() call
               - For ContentProviders: ContentResolver query/insert/update/delete calls with the provider authority
               - For Provider Permission Gap (openFile bypass): Show openFile() call with the opposite mode
                 to bypass the strong permission. E.g., if readPermission is signature-level, call
                 openFile(uri, "w", null) to bypass — the provider may still return a readable fd.
            
            4. IMPACT: What the attacker gains — e.g., access to user data, ability to trigger privileged actions, etc.
            """;

    @Override
    public List<Finding> generateFindings() throws Exception {
        log.info("[*] Starting PermissionChecker POC generation with LLM analysis...");

        ToolsConfig toolsConfig = ConfigContext.getConfig().getToolsConfig();
        LLMClient llmClient = new LLMClient(
                toolsConfig.getLlmApiKey(),
                toolsConfig.getLlmModel(),
                toolsConfig.getLlmBaseUrl()
        );

        PermissionCheckerParser parser = new PermissionCheckerParser();
        PermissionCheckerResult result = parser.parse();

        String manifest = findAndReadManifest();

        log.info("[*] Processing {} permission finding(s) through LLM...", result.getFindings().size());

        List<Finding> findings = new ArrayList<>();
        StringBuilder report = new StringBuilder();
        report.append("# PermissionChecker LLM Analysis Results\n\n");
        report.append("**Date:** ").append(java.time.LocalDateTime.now()).append("\n\n");
        report.append("| # | Check | Permission | Component | Verdict |\n");
        report.append("|---|-------|------------|-----------|--------|\n");

        StringBuilder detailed = new StringBuilder();
        detailed.append("\n---\n\n## Detailed Analysis\n\n");

        int truePositives = 0;
        int falsePositives = 0;

        for (int i = 0; i < result.getFindings().size(); i++) {
            PermissionFinding pf = result.getFindings().get(i);
            log.info("[*] Analyzing finding {}/{}: [{}] {}", i + 1, result.getFindings().size(),
                    pf.getCheck(), pf.getTitle());

            String userPrompt = buildUserPrompt(pf, manifest);

            try {
                String llmResponse = llmClient.chat(SYSTEM_PROMPT, userPrompt);
                boolean isTruePositive = llmResponse.contains("TRUE_POSITIVE");

                if (isTruePositive) {
                    truePositives++;
                    String vulnClass = extractSection(llmResponse, "=== VULNERABILITY CLASS ===", "=== ANALYSIS ===");
                    String analysis = extractSection(llmResponse, "=== ANALYSIS ===", "=== POC ===");
                    String rawPoc = extractSection(llmResponse, "=== POC ===", null);
                    String cleanPoc = cleanPoc(rawPoc);

                    findings.add(Finding.builder()
                            .tool("permissionChecker")
                            .truePositive(true)
                            .sourceFile(pf.getAffectedComponent())
                            .sinkFile(pf.getPermission())
                            .rawFlow(pf.getDescription())
                            .vulnerabilityClass(vulnClass)
                            .analysis(analysis)
                            .poc(cleanPoc)
                            .build());
                } else {
                    falsePositives++;
                    findings.add(Finding.builder()
                            .tool("permissionChecker")
                            .truePositive(false)
                            .sourceFile(pf.getAffectedComponent())
                            .sinkFile(pf.getPermission())
                            .rawFlow(pf.getDescription())
                            .analysis(extractSection(llmResponse, "=== ANALYSIS ===", "=== POC ==="))
                            .build());
                }

                String verdictLabel = isTruePositive ? "✅ TRUE POSITIVE" : "❌ FALSE POSITIVE";
                report.append(String.format("| %d | `%s` | `%s` | `%s` | %s |\n",
                        i + 1, pf.getCheck(), pf.getPermission(), pf.getAffectedComponent(), verdictLabel));

                detailed.append(String.format("### Finding %d\n\n", i + 1));
                detailed.append(String.format("- **Check:** %s\n", pf.getCheck()));
                detailed.append(String.format("- **Title:** %s\n", pf.getTitle()));
                detailed.append(String.format("- **Permission:** `%s`\n", pf.getPermission()));
                detailed.append(String.format("- **Component:** `%s`\n", pf.getAffectedComponent()));
                detailed.append(String.format("- **Verdict:** %s\n\n", verdictLabel));
                detailed.append("#### LLM Response\n\n");
                detailed.append(llmResponse).append("\n\n---\n\n");

                log.info("[*]   Finding {}: {}", i + 1, isTruePositive ? "TRUE POSITIVE" : "FALSE POSITIVE");

            } catch (Exception e) {
                log.error("[!] LLM analysis failed for finding {}: {}", i + 1, e.getMessage());
                findings.add(Finding.builder()
                        .tool("permissionChecker")
                        .truePositive(false)
                        .sourceFile(pf.getAffectedComponent())
                        .sinkFile(pf.getPermission())
                        .rawFlow(pf.getDescription())
                        .vulnerabilityClass(pf.getCheck())
                        .analysis("LLM analysis failed: " + e.getMessage() + ". Manual review required.")
                        .poc(pf.getAttackScenario())
                        .build());
                report.append(String.format("| %d | `%s` | `%s` | `%s` | ⚠️ ERROR |\n",
                        i + 1, pf.getCheck(), pf.getPermission(), pf.getAffectedComponent()));
            }
        }

        report.append(String.format("\n## Summary\n\n| Metric | Count |\n|--------|-------|\n| True Positives | %d |\n| False Positives | %d |\n| **Total** | **%d** |\n",
                truePositives, falsePositives, result.getFindings().size()));
        report.append(detailed);

        String outputPath = Paths.get(PathUtils.getOutputPath(), "permission_checker_poc_results.md").toString();
        try (FileWriter writer = new FileWriter(outputPath)) {
            writer.write(report.toString());
        }

        log.info("[*] PermissionChecker POC results saved to: {}", outputPath);
        log.info("[*] Summary - True Positives: {}, False Positives: {}, Total: {}",
                truePositives, falsePositives, result.getFindings().size());

        return findings;
    }

    private String buildUserPrompt(PermissionFinding finding, String manifest) {
        return "=== PERMISSION FINDING ===\n" +
                "Check: " + finding.getCheck() + "\n" +
                "Severity: " + finding.getSeverity() + "\n" +
                "Title: " + finding.getTitle() + "\n" +
                "Description: " + finding.getDescription() + "\n" +
                "Affected Component: " + finding.getAffectedComponent() + "\n" +
                "Permission: " + finding.getPermission() + "\n" +
                "Recommendation: " + finding.getRecommendation() + "\n" +
                "Attack Scenario: " + finding.getAttackScenario() + "\n\n" +
                "=== ANDROID MANIFEST ===\n" +
                manifest + "\n";
    }

    private String findAndReadManifest() {
        String decompiledPath = PathUtils.getDecompiledApkPath();
        String[] candidates = {
                decompiledPath + "AndroidManifest.xml",
                decompiledPath + "resources/AndroidManifest.xml"
        };
        for (String path : candidates) {
            try {
                if (Files.exists(Path.of(path))) {
                    return Files.readString(Path.of(path));
                }
            } catch (Exception e) {
                log.error("[!] Failed to read manifest: {}", path);
            }
        }
        return "AndroidManifest.xml not found";
    }

    private String extractSection(String response, String startMarker, String endMarker) {
        int startIdx = response.indexOf(startMarker);
        if (startIdx == -1) return "";
        startIdx += startMarker.length();
        int endIdx = (endMarker != null) ? response.indexOf(endMarker, startIdx) : -1;
        String section = (endIdx != -1) ? response.substring(startIdx, endIdx) : response.substring(startIdx);
        return section.trim();
    }

    private String cleanPoc(String rawPoc) {
        if (rawPoc == null || rawPoc.isBlank() || rawPoc.equalsIgnoreCase("N/A")) {
            return rawPoc;
        }
        String cleaned = rawPoc.trim();
        cleaned = cleaned.replaceAll("```\\w*\\s*\\n", "").replaceAll("```", "");
        return cleaned.trim();
    }
}
