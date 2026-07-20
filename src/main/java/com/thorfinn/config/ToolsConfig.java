package com.thorfinn.config;

import lombok.Data;

import java.util.List;

@Data
public class ToolsConfig {
    private String decompilers;
    private List<String> analysisTools;
    private String llmApiKey;
    private String llmModel;
    private String llmBaseUrl;
    private boolean taiEAgentEnabled;
    private int taiEAgentMaxToolResponsePercentage;
    private int cpgTimeLimit;
    private int taiEMaxHeapGb;
    private boolean taiEOnlyApp;
    private List<String> ignoredPackages;
}
