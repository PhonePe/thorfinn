package com.thorfinn.models;

import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@Builder
public class SemgrepResult {

    private int totalFindings;
    private List<SemgrepFinding> findings;

    @Data
    @Builder
    public static class SemgrepFinding {
        private String ruleId;
        private String filePath;
        private int lineNumber;
        private String matchedCode;
        private String message;
        private String severity;
        private Map<String, String> metavars;
    }
}
