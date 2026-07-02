package com.thorfinn.models;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class Finding {
    private String tool;
    private boolean truePositive;
    private String sourceFile;
    private String sinkFile;
    private String rawFlow;
    private String vulnerabilityClass;
    private String analysis;
    private String poc;
}
