package com.thorfinn.decompilers;

import com.thorfinn.utils.CommandRunner;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ApkTool implements Decompilers {
    @Override
    public void decompileApk(String apkPath, String outputPath) throws Exception {
        String result = CommandRunner.runArgs("apktool", "d", apkPath, "-o", outputPath, "-f");
        log.info("APK decompiled successfully. Output: " + result);
    }
}
