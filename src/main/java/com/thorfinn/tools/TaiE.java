package com.thorfinn.tools;

import com.thorfinn.config.ConfigContext;
import com.thorfinn.utils.CommandRunner;
import com.thorfinn.utils.PathUtils;
import lombok.extern.slf4j.Slf4j;

import java.io.FileWriter;
import java.nio.file.Path;
import java.nio.file.Paths;

@Slf4j
public class TaiE implements Tools {

    private static final String TAIE_OUTPUT_FILENAME = "taie_output.txt";

    @Override
    public void execute() throws Exception {
        int timeLimit = ConfigContext.getConfig().getToolsConfig().getCpgTimeLimit();
        int maxHeapGb = resolveMaxHeapGb();
        log.info("[*] TaiE CPG time-limit: {}s", timeLimit);
        log.info("[*] TaiE JVM max heap: {}g", maxHeapGb);
        String result = CommandRunner.run("java -Xmx" + maxHeapGb + "g -XX:+UseG1GC -jar " + PathUtils.getTaiEPath() + " -pp -am -ajs " + PathUtils.getAndroidPlatformsPath() + " -cp " + PathUtils.getApkPath() + " --output-dir " + PathUtils.getTaiEOutputPath() + " -a \"pta=merge-string-objects:true;merge-string-builders:true;merge-exception-objects:true;implicit-entries:false;propagate-types:[reference,int,long,double,char,float];taint-config:" + PathUtils.getTaintConfigPath() + ";distinguish-string-constants:app;reflection-inference:string-constant;time-limit:" + timeLimit + ";\"");

        saveOutputToFile(result);
    }
    private int resolveMaxHeapGb() {
        int configured = ConfigContext.getConfig().getToolsConfig().getTaiEMaxHeapGb();
        if (configured > 0) {
            return configured;
        }

        java.lang.management.OperatingSystemMXBean osBean =
                java.lang.management.ManagementFactory.getOperatingSystemMXBean();
        if (osBean instanceof com.sun.management.OperatingSystemMXBean sunOsBean) {
            long totalGb = sunOsBean.getTotalMemorySize() / (1024L * 1024L * 1024L);
            return (int) (totalGb * 3 / 4);
        }
        throw new IllegalStateException(
                "Could not auto-detect physical memory for Tai-e heap sizing; set taiEMaxHeapGb in config.");
    }

    private void saveOutputToFile(String output) {
        try {
            Path outputFile = Paths.get(PathUtils.getOutputPath(), TAIE_OUTPUT_FILENAME);

            try (FileWriter writer = new FileWriter(outputFile.toFile())) {
                writer.write(output);
            }

            log.info("[*] TaiE output saved to: {}", outputFile.toAbsolutePath());
        } catch (Exception e) {
            log.error("[!] Failed to save taie output to file: {}", e.getMessage());
        }
    }
}
