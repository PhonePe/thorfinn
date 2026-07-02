package com.thorfinn.config;

import lombok.Data;

@Data
public class PathConfigs {
    private String decompiledApkPath;
    private String taiePath;
    private String androidPlatformsPath;
    private String taieOutputPath;
    private String taintConfigPath;
    private String permissionCheckerPath;
    private String semgrepRulesPath;
    private String outputPath;
    private String apkPath;
}
