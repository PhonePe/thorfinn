package com.thorfinn.decompilers;

import com.thorfinn.utils.CommandRunner;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JADXTool implements Decompilers {

    @Override
    public void decompileApk(String apkPath, String outputPath) throws Exception {
        log.info("[*] Decompiling APK using JADX: {} -> {}", apkPath, outputPath);
        try {
            CommandRunner.runArgs("jadx", "-d", outputPath, apkPath, "--show-bad-code", "--deobf");
            log.info("[*] JADX decompilation complete. Output: {}", outputPath);
        } catch (RuntimeException e) {
            log.warn("[!] JADX finished with some errors (this is normal): {}", e.getMessage().split("\n")[0]);
        }
    }
}
