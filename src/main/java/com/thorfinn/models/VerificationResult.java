package com.thorfinn.models;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class VerificationResult {
    private Finding finding;
    private boolean truePositive;
    private String status;
    private String commandExecuted;
    private String output;
    private String errorMessage;
    private List<String> evidence;
}
