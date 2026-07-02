package com.thorfinn.models;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class ManifestInfo {

    private String packageName;
    private String versionName;
    private String versionCode;
    private String minSdkVersion;
    private String targetSdkVersion;
    private boolean debuggable;
    private boolean allowBackup;
    private boolean usesCleartextTraffic;

    private List<String> permissions;
    private List<ExportedComponent> exportedActivities;
    private List<ExportedComponent> exportedServices;
    private List<ExportedComponent> exportedReceivers;
    private List<ExportedComponent> exportedProviders;

    @Data
    @Builder
    public static class ExportedComponent {
        private String name;
        private String permission;
        private List<String> intentFilters;
    }
}
