package com.thorfinn.cvss;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.thorfinn.config.Config;
import com.thorfinn.config.ConfigContext;
import com.thorfinn.config.CvssConfig.CvssMetricDefinition;
import com.thorfinn.models.Finding;
import com.thorfinn.models.VerificationResult;

import lombok.extern.slf4j.Slf4j;
import us.springett.cvss.CvssV4;
import us.springett.cvss.Score;

@Slf4j
public class FindingSeverityService {

    private static final Map<String, CvssMetricDefinition> DEFAULT_METRIC_MATRIX = new HashMap<>();

    static {
        DEFAULT_METRIC_MATRIX.put("Arbitrary File Write", CvssMetricDefinition.builder()
                .attackVector("LOCAL")
                .attackComplexity("LOW")
                .attackRequirements("NONE")
                .privilegesRequired("NONE")
                .userInteraction("NONE")
                .vulnerableSystemConfidentiality("NONE")
                .vulnerableSystemIntegrity("HIGH")
                .vulnerableSystemAvailability("HIGH")
                .subsequentSystemConfidentiality("NONE")
                .subsequentSystemIntegrity("NONE")
                .subsequentSystemAvailability("NONE")
                .build());

        DEFAULT_METRIC_MATRIX.put("Third-Party Package Context Code Execution", CvssMetricDefinition.builder()
                .attackVector("LOCAL")
                .attackComplexity("LOW")
                .attackRequirements("NONE")
                .privilegesRequired("NONE")
                .userInteraction("NONE")
                .vulnerableSystemConfidentiality("HIGH")
                .vulnerableSystemIntegrity("HIGH")
                .vulnerableSystemAvailability("HIGH")
                .subsequentSystemConfidentiality("NONE")
                .subsequentSystemIntegrity("NONE")
                .subsequentSystemAvailability("NONE")
                .build());

        DEFAULT_METRIC_MATRIX.put("SQL Injection", CvssMetricDefinition.builder()
                .attackVector("LOCAL")
                .attackComplexity("LOW")
                .attackRequirements("NONE")
                .privilegesRequired("NONE")
                .userInteraction("NONE")
                .vulnerableSystemConfidentiality("HIGH")
                .vulnerableSystemIntegrity("HIGH")
                .vulnerableSystemAvailability("LOW")
                .subsequentSystemConfidentiality("NONE")
                .subsequentSystemIntegrity("NONE")
                .subsequentSystemAvailability("NONE")
                .build());

        DEFAULT_METRIC_MATRIX.put("Intent Redirection", CvssMetricDefinition.builder()
                .attackVector("LOCAL")
                .attackComplexity("LOW")
                .attackRequirements("NONE")
                .privilegesRequired("NONE")
                .userInteraction("NONE")
                .vulnerableSystemConfidentiality("HIGH")
                .vulnerableSystemIntegrity("HIGH")
                .vulnerableSystemAvailability("NONE")
                .subsequentSystemConfidentiality("HIGH")
                .subsequentSystemIntegrity("HIGH")
                .subsequentSystemAvailability("NONE")
                .build());

        DEFAULT_METRIC_MATRIX.put("Path Traversal in Content Providers", CvssMetricDefinition.builder()
                .attackVector("LOCAL")
                .attackComplexity("LOW")
                .attackRequirements("NONE")
                .privilegesRequired("NONE")
                .userInteraction("NONE")
                .vulnerableSystemConfidentiality("HIGH").vulnerableSystemIntegrity("HIGH").vulnerableSystemAvailability("NONE")
                .subsequentSystemConfidentiality("NONE").subsequentSystemIntegrity("NONE").subsequentSystemAvailability("NONE")
                .build());

        DEFAULT_METRIC_MATRIX.put("Content Provider Proxy / URI Forwarding", CvssMetricDefinition.builder()
                .attackVector("LOCAL")
                .attackComplexity("LOW")
                .attackRequirements("NONE")
                .privilegesRequired("NONE")
                .userInteraction("NONE")
                .vulnerableSystemConfidentiality("HIGH")
                .vulnerableSystemIntegrity("HIGH")
                .vulnerableSystemAvailability("NONE")
                .subsequentSystemConfidentiality("HIGH")
                .subsequentSystemIntegrity("HIGH")
                .subsequentSystemAvailability("NONE")
                .build());

        DEFAULT_METRIC_MATRIX.put("PendingIntent Redirection", CvssMetricDefinition.builder()
                .attackVector("LOCAL")
                .attackComplexity("LOW")
                .attackRequirements("NONE")
                .privilegesRequired("NONE")
                .userInteraction("NONE")
                .vulnerableSystemConfidentiality("HIGH").vulnerableSystemIntegrity("HIGH").vulnerableSystemAvailability("NONE")
                .subsequentSystemConfidentiality("HIGH").subsequentSystemIntegrity("HIGH").subsequentSystemAvailability("NONE")
                .build());

        DEFAULT_METRIC_MATRIX.put("WebView Vulnerability", CvssMetricDefinition.builder()
                .attackVector("NETWORK")
                .attackComplexity("LOW")
                .attackRequirements("NONE")
                .privilegesRequired("NONE")
                .userInteraction("PASSIVE")
                .vulnerableSystemConfidentiality("HIGH").vulnerableSystemIntegrity("HIGH").vulnerableSystemAvailability("NONE")
                .subsequentSystemConfidentiality("LOW").subsequentSystemIntegrity("LOW").subsequentSystemAvailability("NONE")
                .build());

        DEFAULT_METRIC_MATRIX.put("CustomTabIntent Vulnerability", CvssMetricDefinition.builder()
                .attackVector("NETWORK").attackComplexity("LOW").attackRequirements("NONE")
                .privilegesRequired("NONE").userInteraction("PASSIVE")
                .vulnerableSystemConfidentiality("LOW").vulnerableSystemIntegrity("LOW").vulnerableSystemAvailability("NONE")
                .subsequentSystemConfidentiality("NONE").subsequentSystemIntegrity("NONE").subsequentSystemAvailability("NONE")
                .build());

        DEFAULT_METRIC_MATRIX.put("Dynamic Broadcast Receiver", CvssMetricDefinition.builder()
                .attackVector("LOCAL")
                .attackComplexity("LOW")
                .attackRequirements("NONE")
                .privilegesRequired("NONE")
                .userInteraction("NONE")
                .vulnerableSystemConfidentiality("LOW")
                .vulnerableSystemIntegrity("LOW")
                .vulnerableSystemAvailability("LOW")
                .subsequentSystemConfidentiality("NONE")
                .subsequentSystemIntegrity("NONE")
                .subsequentSystemAvailability("NONE")
                .build());

        DEFAULT_METRIC_MATRIX.put("Changing Device Settings", CvssMetricDefinition.builder()
                .attackVector("LOCAL")
                .attackComplexity("LOW")
                .attackRequirements("NONE")
                .privilegesRequired("NONE")
                .userInteraction("NONE")
                .vulnerableSystemConfidentiality("NONE")
                .vulnerableSystemIntegrity("LOW")
                .vulnerableSystemAvailability("LOW")
                .subsequentSystemConfidentiality("NONE")
                .subsequentSystemIntegrity("NONE")
                .subsequentSystemAvailability("NONE")
                .build());

        DEFAULT_METRIC_MATRIX.put("Implicit Intent Interception", CvssMetricDefinition.builder()
                .attackVector("LOCAL")
                .attackComplexity("LOW")
                .attackRequirements("NONE")
                .privilegesRequired("NONE")
                .userInteraction("PASSIVE")
                .vulnerableSystemConfidentiality("HIGH")
                .vulnerableSystemIntegrity("NONE")
                .vulnerableSystemAvailability("NONE")
                .subsequentSystemConfidentiality("NONE")
                .subsequentSystemIntegrity("NONE")
                .subsequentSystemAvailability("NONE")
                .build());

        DEFAULT_METRIC_MATRIX.put("Missing protectionLevel", CvssMetricDefinition.builder()
                .attackVector("LOCAL")
                .attackComplexity("LOW")
                .attackRequirements("NONE")
                .privilegesRequired("NONE")
                .userInteraction("NONE")
                .vulnerableSystemConfidentiality("HIGH")
                .vulnerableSystemIntegrity("HIGH")
                .vulnerableSystemAvailability("NONE")
                .subsequentSystemConfidentiality("NONE")
                .subsequentSystemIntegrity("NONE")
                .subsequentSystemAvailability("NONE")
                .build());

        DEFAULT_METRIC_MATRIX.put("Permission Name Typo", CvssMetricDefinition.builder()
                .attackVector("LOCAL")
                .attackComplexity("LOW")
                .attackRequirements("NONE")
                .privilegesRequired("NONE")
                .userInteraction("NONE")
                .vulnerableSystemConfidentiality("HIGH")
                .vulnerableSystemIntegrity("HIGH")
                .vulnerableSystemAvailability("NONE")
                .subsequentSystemConfidentiality("NONE")
                .subsequentSystemIntegrity("NONE")
                .subsequentSystemAvailability("NONE")
                .build());

        DEFAULT_METRIC_MATRIX.put("Component Attribute Typo", CvssMetricDefinition.builder()
                .attackVector("LOCAL")
                .attackComplexity("LOW")
                .attackRequirements("NONE")
                .privilegesRequired("NONE")
                .userInteraction("NONE")
                .vulnerableSystemConfidentiality("HIGH")
                .vulnerableSystemIntegrity("HIGH")
                .vulnerableSystemAvailability("NONE")
                .subsequentSystemConfidentiality("NONE")
                .subsequentSystemIntegrity("NONE")
                .subsequentSystemAvailability("NONE")
                .build());

        DEFAULT_METRIC_MATRIX.put("Provider Permission Gap", CvssMetricDefinition.builder()
                .attackVector("LOCAL")
                .attackComplexity("LOW")
                .attackRequirements("NONE")
                .privilegesRequired("NONE")
                .userInteraction("NONE")
                .vulnerableSystemConfidentiality("HIGH")
                .vulnerableSystemIntegrity("NONE")
                .vulnerableSystemAvailability("NONE")
                .subsequentSystemConfidentiality("NONE")
                .subsequentSystemIntegrity("NONE")
                .subsequentSystemAvailability("NONE")
                .build());

        DEFAULT_METRIC_MATRIX.put("Ecosystem Permission Issue", CvssMetricDefinition.builder()
                .attackVector("LOCAL")
                .attackComplexity("LOW")
                .attackRequirements("NONE")
                .privilegesRequired("LOW")
                .userInteraction("NONE")
                .vulnerableSystemConfidentiality("LOW")
                .vulnerableSystemIntegrity("LOW")
                .vulnerableSystemAvailability("NONE")
                .subsequentSystemConfidentiality("NONE")
                .subsequentSystemIntegrity("NONE")
                .subsequentSystemAvailability("NONE")
                .build());

        DEFAULT_METRIC_MATRIX.put("Hardcoded Secret / API Key / Token", CvssMetricDefinition.builder()
                .attackVector("LOCAL")
                .attackComplexity("LOW")
                .attackRequirements("NONE")
                .privilegesRequired("NONE")
                .userInteraction("NONE")
                .vulnerableSystemConfidentiality("HIGH")
                .vulnerableSystemIntegrity("LOW")
                .vulnerableSystemAvailability("NONE")
                .subsequentSystemConfidentiality("NONE")
                .subsequentSystemIntegrity("NONE")
                .subsequentSystemAvailability("NONE")
                .build());

        DEFAULT_METRIC_MATRIX.put("default", CvssMetricDefinition.builder()
                .attackVector("LOCAL")
                .attackComplexity("LOW")
                .attackRequirements("NONE")
                .privilegesRequired("NONE")
                .userInteraction("NONE")
                .vulnerableSystemConfidentiality("LOW")
                .vulnerableSystemIntegrity("LOW")
                .vulnerableSystemAvailability("NONE")
                .subsequentSystemConfidentiality("NONE")
                .subsequentSystemIntegrity("NONE")
                .subsequentSystemAvailability("NONE")
                .build());
    }

    public void assignSeverities(List<VerificationResult> results) {
        if (results == null) {
            return;
        }
        for (VerificationResult r : results) {
            Finding f = r.getFinding();
            if (f == null) {
                continue;
            }
            boolean isDeviceVerified = isVerified(r);
            evaluateFinding(f, isDeviceVerified);
        }
    }

    public void evaluateFinding(Finding finding, boolean isDeviceVerified) {
        if (finding == null) {
            return;
        }

        if (finding.isAnalysisError()) {
            finding.setSeverity("UNKNOWN");
            finding.setCvssScore(null);
            finding.setCvssBaseScore(null);
            finding.setCvssVector(null);
            return;
        }

        CvssMetricDefinition def = resolveMetricDefinition(finding.getVulnerabilityClass(), finding.getTool());

        CvssV4 baseCvss = buildCvssV4(def);
        baseCvss.exploitMaturity(CvssV4.ExploitMaturity.NOT_DEFINED);
        Score baseScoreObj = baseCvss.calculateScore();
        double baseScore = baseScoreObj.getBaseScore();
        finding.setCvssBaseScore(baseScore);

        if (!finding.isTruePositive()) {
            finding.setSeverity("NONE");
            finding.setCvssScore(0.0);
            finding.setCvssVector(baseCvss.getVector());
            return;
        }

        boolean hasPoc = finding.getPoc() != null && !finding.getPoc().isBlank() && !"N/A".equalsIgnoreCase(finding.getPoc().trim());

        CvssV4 threatCvss = buildCvssV4(def);
        if (hasPoc && isDeviceVerified) {
            threatCvss.exploitMaturity(CvssV4.ExploitMaturity.ATTACKED);
        } else if (hasPoc) {
            threatCvss.exploitMaturity(CvssV4.ExploitMaturity.POC);
        } else {
            threatCvss.exploitMaturity(CvssV4.ExploitMaturity.UNREPORTED);
        }

        Score threatScoreObj = threatCvss.calculateScore();
        double finalScore = threatScoreObj.getBaseScore();

        finding.setCvssScore(finalScore);
        finding.setCvssVector(threatCvss.getVector());
        finding.setSeverity(scoreToSeverity(finalScore));

        log.debug("[*] Finding [{} -> {}] Severity: {} (Score: {}, Base: {}, Vector: {})",
                finding.getSourceFile(), finding.getSinkFile(),
                finding.getSeverity(), finding.getCvssScore(), finding.getCvssBaseScore(), finding.getCvssVector());
    }

    private boolean isVerified(VerificationResult r) {
        if (r == null) {
            return false;
        }
        String status = r.getStatus();
        if ("SUCCESS".equalsIgnoreCase(status) || "VERIFIED".equalsIgnoreCase(status)) {
            return true;
        }
        return r.getEvidence() != null && !r.getEvidence().isEmpty();
    }

    private CvssMetricDefinition resolveMetricDefinition(String vulnClass, String tool) {
        Map<String, CvssMetricDefinition> configuredMatrix = null;
        Config config = ConfigContext.getConfig();
        if (config != null && config.getCvssConfig() != null) {
            configuredMatrix = config.getCvssConfig().getMetricMatrix();
        }

        if (configuredMatrix != null && !configuredMatrix.isEmpty()) {
            if (vulnClass != null) {
                CvssMetricDefinition match = findInMapIgnoreCase(configuredMatrix, vulnClass);
                if (match != null) {
                    return match;
                }
            }
            if ("truffleHog".equalsIgnoreCase(tool)) {
                CvssMetricDefinition match = findInMapIgnoreCase(configuredMatrix, "Hardcoded Secret / API Key / Token");
                if (match != null) {
                    return match;
                }
            }
            CvssMetricDefinition defaultMatch = findInMapIgnoreCase(configuredMatrix, "default");
            if (defaultMatch != null) {
                return defaultMatch;
            }
        }

        if (vulnClass != null) {
            CvssMetricDefinition match = findInMapIgnoreCase(DEFAULT_METRIC_MATRIX, vulnClass);
            if (match != null) {
                return match;
            }
        }
        if ("truffleHog".equalsIgnoreCase(tool)) {
            return DEFAULT_METRIC_MATRIX.get("Hardcoded Secret / API Key / Token");
        }
        return DEFAULT_METRIC_MATRIX.get("default");
    }

    private CvssMetricDefinition findInMapIgnoreCase(Map<String, CvssMetricDefinition> map, String key) {
        if (map == null || key == null) {
            return null;
        }
        for (Map.Entry<String, CvssMetricDefinition> entry : map.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(key.trim())) {
                return entry.getValue();
            }
        }
        return null;
    }

    private CvssV4 buildCvssV4(CvssMetricDefinition def) {
        CvssV4 cvss = new CvssV4();
        cvss.attackVector(parseAttackVector(def.getAttackVector()));
        cvss.attackComplexity(parseAttackComplexity(def.getAttackComplexity()));
        cvss.attackRequirements(parseAttackRequirements(def.getAttackRequirements()));
        cvss.privilegesRequired(parsePrivilegesRequired(def.getPrivilegesRequired()));
        cvss.userInteraction(parseUserInteraction(def.getUserInteraction()));
        cvss.confidentialityImpact(parseImpact(def.getVulnerableSystemConfidentiality()));
        cvss.integrityImpact(parseImpact(def.getVulnerableSystemIntegrity()));
        cvss.availabilityImpact(parseImpact(def.getVulnerableSystemAvailability()));
        cvss.subsequentConfidentiality(parseImpact(def.getSubsequentSystemConfidentiality()));
        cvss.subsequentIntegrity(parseImpact(def.getSubsequentSystemIntegrity()));
        cvss.subsequentAvailability(parseImpact(def.getSubsequentSystemAvailability()));
        return cvss;
    }

    private CvssV4.AttackVector parseAttackVector(String val) {
        if (val == null || val.isBlank()) {
            return CvssV4.AttackVector.LOCAL;
        }
        try {
            return CvssV4.AttackVector.valueOf(val.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return CvssV4.AttackVector.LOCAL;
        }
    }

    private CvssV4.AttackComplexity parseAttackComplexity(String val) {
        if (val == null || val.isBlank()) {
            return CvssV4.AttackComplexity.LOW;
        }
        try {
            return CvssV4.AttackComplexity.valueOf(val.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return CvssV4.AttackComplexity.LOW;
        }
    }

    private CvssV4.AttackRequirements parseAttackRequirements(String val) {
        if (val == null || val.isBlank()) {
            return CvssV4.AttackRequirements.NONE;
        }
        try {
            return CvssV4.AttackRequirements.valueOf(val.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return CvssV4.AttackRequirements.NONE;
        }
    }

    private CvssV4.PrivilegesRequired parsePrivilegesRequired(String val) {
        if (val == null || val.isBlank()) {
            return CvssV4.PrivilegesRequired.NONE;
        }
        try {
            return CvssV4.PrivilegesRequired.valueOf(val.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return CvssV4.PrivilegesRequired.NONE;
        }
    }

    private CvssV4.UserInteraction parseUserInteraction(String val) {
        if (val == null || val.isBlank()) {
            return CvssV4.UserInteraction.NONE;
        }
        try {
            return CvssV4.UserInteraction.valueOf(val.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return CvssV4.UserInteraction.NONE;
        }
    }

    private CvssV4.Impact parseImpact(String val) {
        if (val == null || val.isBlank()) {
            return CvssV4.Impact.NONE;
        }
        try {
            return CvssV4.Impact.valueOf(val.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return CvssV4.Impact.NONE;
        }
    }

    public static String scoreToSeverity(double score) {
        if (score >= 9.0) {
            return "CRITICAL";
        }
        if (score >= 7.0) {
            return "HIGH";
        }
        if (score >= 4.0) {
            return "MEDIUM";
        }
        if (score > 0.0) {
            return "LOW";
        }
        return "NONE";
    }
}
