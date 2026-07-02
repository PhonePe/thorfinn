package com.thorfinn.decompilers;

public interface Decompilers {
    public void decompileApk(String apkPath, String outputPath) throws Exception;
}
