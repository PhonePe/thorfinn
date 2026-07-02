package com.thorfinn.models;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class PermissionCheckerResult {

    private String manifest;
    private String packageName;
    private int totalFindings;
    private List<PermissionFinding> findings;

    @Data
    @Builder
    public static class PermissionFinding {
        private String check;
        private String severity;
        private String title;
        private String description;
        private String affectedComponent;
        private String permission;
        private String recommendation;
        private String attackScenario;
    }
}
