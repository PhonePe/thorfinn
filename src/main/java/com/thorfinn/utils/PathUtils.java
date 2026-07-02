package com.thorfinn.utils;

import com.thorfinn.config.ConfigContext;

public class PathUtils {


    public static String getBaseDirectory() {
        return System.getProperty("user.dir");
    }

    public static String getApkPath() {
        return ConfigContext.getConfig().getPathConfigs().getApkPath();
    }

    public static String getDecompiledApkPath() {
        return getBaseDirectory() + ConfigContext.getConfig().getPathConfigs().getDecompiledApkPath();
    }

    public static String getTaiEPath() {
        return getBaseDirectory() + ConfigContext.getConfig().getPathConfigs().getTaiePath();
    }

    public static String getAndroidPlatformsPath() {
        return getBaseDirectory() + ConfigContext.getConfig().getPathConfigs().getAndroidPlatformsPath();
    }

    public static String getTaiEOutputPath() {
        return getBaseDirectory() + ConfigContext.getConfig().getPathConfigs().getTaieOutputPath();
    }

    public static String getTaintConfigPath() {
        return getBaseDirectory() + ConfigContext.getConfig().getPathConfigs().getTaintConfigPath();
    }

    public static String getPermissionCheckerPath() {
        return getBaseDirectory() + ConfigContext.getConfig().getPathConfigs().getPermissionCheckerPath();
    }

    public static String getSemgrepRulesPath() {
        return getBaseDirectory() + ConfigContext.getConfig().getPathConfigs().getSemgrepRulesPath();
    }

    public static String getOutputPath() {
        return getBaseDirectory() + ConfigContext.getConfig().getPathConfigs().getOutputPath();
    }

}
