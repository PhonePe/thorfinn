package com.thorfinn.models;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class TaiEResult {

    private int totalFlowsDetected;
    private List<TaintFlowInfo> taintFlows;

    @Data
    @Builder
    public static class TaintFlowInfo {
        private String sourceFile;
        private String sinkFile;
        private String rawFlow;
        private List<String> intermediateClasses;
        private List<String> allInvolvedClasses;
        private List<String> flowPath;
        private String flowDescription;
    }
}
