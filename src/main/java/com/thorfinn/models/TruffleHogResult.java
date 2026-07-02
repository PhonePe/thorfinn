package com.thorfinn.models;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class TruffleHogResult {

    private int totalFindings;
    private List<SecretFinding> findings;

    @Data
    @Builder
    public static class SecretFinding {
        private String filePath;
        private int lineNumber;
        private String raw;
    }
}
