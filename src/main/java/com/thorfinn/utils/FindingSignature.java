package com.thorfinn.utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class FindingSignature {

    private FindingSignature() {
    }

    public static String compute(String tool, String sourceFile, String sinkFile, String rawFlow) {
        String canonical = String.join("\u0000",
                nullSafe(tool),
                nullSafe(toRelativePath(sourceFile)),
                nullSafe(toRelativePath(sinkFile)),
                nullSafe(rawFlow));
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(canonical.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                hex.append(Character.forDigit((b >> 4) & 0xF, 16));
                hex.append(Character.forDigit(b & 0xF, 16));
            }
            return "sha256:" + hex;
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed present on every JVM; this should never happen.
            return "sha256:" + Integer.toHexString(canonical.hashCode());
        }
    }

    public static String toRelativePath(String absolutePath) {
        if (absolutePath == null || absolutePath.isBlank()) return "";
        int idx = absolutePath.indexOf("decompiled_apks/");
        if (idx != -1) {
            return absolutePath.substring(idx + "decompiled_apks/".length());
        }
        idx = absolutePath.indexOf("sources/");
        if (idx != -1) {
            return absolutePath.substring(idx);
        }
        return absolutePath;
    }

    private static String nullSafe(String value) {
        return value == null ? "" : value;
    }
}

