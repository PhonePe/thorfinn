package com.thorfinn.models;

import com.fasterxml.jackson.annotation.JsonClassDescription;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;

import java.util.List;

public final class TaiEAgentModels {

    private TaiEAgentModels() {
    }

    @JsonClassDescription("Input for TaiE flow-level agent analysis.")
    public record FlowRequest(
            @JsonPropertyDescription("Source class name from the taint flow.") String sourceClass,
            @JsonPropertyDescription("Sink class name from the taint flow.") String sinkClass,
            @JsonPropertyDescription("Raw taint flow string from TaiE output.") String rawFlow,
            @JsonPropertyDescription("Expanded flow description if available.") String flowDescription,
            @JsonPropertyDescription("Ordered list of classes in the flow path.") List<String> allInvolvedClasses
    ) {
    }

    @JsonClassDescription("Structured output expected from TaiE flow-level agent.")
    public record FlowResponse(
            @JsonPropertyDescription("Final verdict for this source-sink pair. Must be TRUE_POSITIVE or FALSE_POSITIVE.") String verdict,
            @JsonPropertyDescription("Vulnerability class label. Use N/A for false positives.") String vulnerabilityClass,
            @JsonPropertyDescription("Detailed reasoning specific to this flow only.") String analysis,
            @JsonPropertyDescription("Executable POC or NO_ADB_COMMAND block when adb is not possible.") String poc
    ) {
    }
}
