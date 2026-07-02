package com.thorfinn.utils;

import java.io.InputStream;
import java.util.Properties;

public final class VersionInfo {

    private static final String POM_PROPS =
            "META-INF/maven/com.thorfinn/Thorfinn/pom.properties";

    private static final String VERSION = resolve();

    private VersionInfo() {}

    public static String getVersion() {
        return VERSION;
    }

    private static String resolve() {
        String v = VersionInfo.class.getPackage().getImplementationVersion();
        if (v != null && !v.isBlank()) {
            return normalize(v);
        }

        try (InputStream in = VersionInfo.class.getClassLoader().getResourceAsStream(POM_PROPS)) {
            if (in != null) {
                Properties props = new Properties();
                props.load(in);
                String pv = props.getProperty("version");
                if (pv != null && !pv.isBlank()) {
                    return normalize(pv);
                }
            }
        } catch (Exception ignored) {
        }
        return "dev";
    }


    private static String normalize(String v) {
        return v.startsWith("v") ? v : "v" + v;
    }
}

