package com.thorfinn.poc;

import com.thorfinn.config.ConfigContext;
import com.thorfinn.config.ToolsConfig;
import com.thorfinn.models.Finding;
import com.thorfinn.models.TruffleHogResult;
import com.thorfinn.models.TruffleHogResult.SecretFinding;
import com.thorfinn.parsers.TruffleHogParser;
import com.thorfinn.utils.LLMClient;
import com.thorfinn.utils.PathUtils;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

@Slf4j
public class TruffleHogPOC implements poc {

    private static final String SYSTEM_PROMPT = """
            You are an expert application security researcher specializing in hardcoded secrets in mobile applications.
            
            You will be given a secret found by TruffleHog in a decompiled Android APK. The finding includes:
            - The file path where the secret was found
            - The line number
            - The raw secret value
            - The FULL content of the file for context
            
            IMPORTANT: You are evaluating ONLY the specific secret value provided in "Raw Secret" below.
            Do NOT evaluate other secrets or sensitive values in the file. Focus ONLY on the one secret given.
            
            YOUR JOB:
            Determine if this specific secret is a TRUE POSITIVE (real secret that should not be in client code) or FALSE POSITIVE.
            
            FALSE POSITIVE examples:
            - Placeholder/example values, test keys
            - Public API keys meant to be client-side (e.g., Firebase web API keys, Google Maps Android keys)
            - Dummy values like "changeme", "TODO", "xxx", "your-api-key-here"
            - Keys that are publicly documented or meant for client distribution
            
            TRUE POSITIVE examples:
            - Private keys, server-side API keys
            - Credentials with passwords
            - Tokens that grant access to sensitive resources
            - AWS/GCP/Azure service account keys
            - Database connection strings with credentials
            - Any secret that gives unauthorized access to backend systems
            
            RESPONSE FORMAT:
            
            === VERDICT ===
            TRUE_POSITIVE or FALSE_POSITIVE
            
            === ANALYSIS ===
            (Your reasoning for THIS specific secret — what it is, why it is or isn't a real leaked secret.)
            """;

    @Override
    public List<Finding> generateFindings() throws Exception {
        log.info("[*] Starting TruffleHog POC generation with LLM analysis...");

        ToolsConfig toolsConfig = ConfigContext.getConfig().getToolsConfig();
        LLMClient llmClient = new LLMClient(
                toolsConfig.getLlmApiKey(),
                toolsConfig.getLlmModel(),
                toolsConfig.getLlmBaseUrl()
        );

        TruffleHogParser parser = new TruffleHogParser();
        TruffleHogResult result = parser.parse();

        log.info("[*] Processing {} secret(s) through LLM...", result.getTotalFindings());

        List<Finding> findings = new ArrayList<>();

        for (int i = 0; i < result.getFindings().size(); i++) {
            SecretFinding sf = result.getFindings().get(i);
            log.info("[*] Analyzing secret {}/{}: {} (line {})",
                    i + 1, result.getTotalFindings(), sf.getFilePath(), sf.getLineNumber());

            String fileContent = findAndReadFile(sf.getFilePath());
            String userPrompt = buildUserPrompt(sf, fileContent);

            try {
                String llmResponse = llmClient.chat(SYSTEM_PROMPT, userPrompt);
                boolean isTruePositive = llmResponse.contains("TRUE_POSITIVE");

                String analysis = extractSection(llmResponse, "=== ANALYSIS ===", null);

                findings.add(Finding.builder()
                        .tool("truffleHog")
                        .truePositive(isTruePositive)
                        .sourceFile(sf.getFilePath())
                        .sinkFile("line " + sf.getLineNumber())
                        .rawFlow(sf.getRaw())
                        .vulnerabilityClass("Hardcoded Secrets")
                        .analysis(analysis)
                        .build());

                log.info("[*]   Secret {}: {}", i + 1, isTruePositive ? "TRUE POSITIVE" : "FALSE POSITIVE");

            } catch (Exception e) {
                log.error("[!] LLM analysis failed for secret {}: {}", i + 1, e.getMessage());
                findings.add(Finding.builder()
                        .tool("truffleHog")
                        .truePositive(false)
                        .sourceFile(sf.getFilePath())
                        .sinkFile("line " + sf.getLineNumber())
                        .rawFlow(sf.getRaw())
                        .vulnerabilityClass("Hardcoded Secrets")
                        .analysis("LLM analysis failed: " + e.getMessage() + ". Manual review required.")
                        .build());
            }
        }

        log.info("[*] TruffleHog POC generation complete. Findings: {}", findings.size());
        return findings;
    }

    private String buildUserPrompt(SecretFinding finding, String fileContent) {
        return "=== SECRET FINDING ===\n" +
                "File: " + finding.getFilePath() + "\n" +
                "Line: " + finding.getLineNumber() + "\n" +
                "Raw Secret: " + finding.getRaw() + "\n\n" +
                "=== FULL FILE CONTENT ===\n" +
                fileContent + "\n";
    }

    private String findAndReadFile(String relativePath) {
        String decompiledPath = PathUtils.getDecompiledApkPath();

        File file = new File(decompiledPath, relativePath);
        if (file.exists()) {
            try {
                log.info("[*]   Found file: {}", file.getPath());
                return Files.readString(file.toPath());
            } catch (Exception e) {
                log.error("[!] Failed to read file: {}", file.getPath());
            }
        }

        String fileName = Path.of(relativePath).getFileName().toString();
        log.info("[*]   Exact path not found for {}, initiating fuzzy search...", relativePath);

        File baseDir = new File(decompiledPath);
        if (!baseDir.exists()) {
            return "File not found: " + relativePath;
        }

        List<File> candidates = new ArrayList<>();
        findFilesByName(baseDir, fileName, candidates);

        if (candidates.isEmpty()) {
            log.warn("[!] File not found (even fuzzy): {}", relativePath);
            return "File not found: " + relativePath;
        }

        String[] originalParts = relativePath.replace(File.separatorChar, '/').split("/");
        File bestMatch = null;
        int bestScore = -1;

        for (File candidate : candidates) {
            String candidateRelative = baseDir.toPath().relativize(candidate.toPath()).toString();
            String[] candidateParts = candidateRelative.replace(File.separatorChar, '/').split("/");

            int score = 0;
            int minLen = Math.min(originalParts.length, candidateParts.length);
            for (int j = 0; j < minLen; j++) {
                if (originalParts[j].equals(candidateParts[j])) {
                    score++;
                }
            }
            if (score > bestScore) {
                bestScore = score;
                bestMatch = candidate;
            }
        }

        if (bestMatch != null) {
            try {
                log.info("[*]   Found file (fuzzy match): {}", bestMatch.getPath());
                return Files.readString(bestMatch.toPath());
            } catch (Exception e) {
                log.error("[!] Failed to read file: {}", bestMatch.getPath());
            }
        }

        return "File not found: " + relativePath;
    }

    private void findFilesByName(File dir, String fileName, List<File> results) {
        File[] children = dir.listFiles();
        if (children == null) return;
        for (File child : children) {
            if (child.isDirectory()) {
                findFilesByName(child, fileName, results);
            } else if (child.getName().equals(fileName)) {
                results.add(child);
            }
        }
    }

    private String extractSection(String response, String startMarker, String endMarker) {
        int startIdx = response.indexOf(startMarker);
        if (startIdx == -1) return "";
        startIdx += startMarker.length();
        int endIdx = (endMarker != null) ? response.indexOf(endMarker, startIdx) : -1;
        String section = (endIdx != -1) ? response.substring(startIdx, endIdx) : response.substring(startIdx);
        return section.trim();
    }
}
