package com.thorfinn.config;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CvssConfig {
    private Map<String, CvssMetricDefinition> metricMatrix;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CvssMetricDefinition {
        private String attackVector;
        private String attackComplexity;
        private String attackRequirements;
        private String privilegesRequired;
        private String userInteraction;
        private String vulnerableSystemConfidentiality;
        private String vulnerableSystemIntegrity;
        private String vulnerableSystemAvailability;
        private String subsequentSystemConfidentiality;
        private String subsequentSystemIntegrity;
        private String subsequentSystemAvailability;
    }
}
