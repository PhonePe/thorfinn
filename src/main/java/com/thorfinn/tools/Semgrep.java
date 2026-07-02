package com.thorfinn.tools;

import com.thorfinn.utils.CommandRunner;
import com.thorfinn.utils.PathUtils;
import lombok.extern.slf4j.Slf4j;

import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Slf4j
public class Semgrep implements Tools {

    private static final String OUTPUT_FILENAME = "semgrep_output.json";

    @Override
    public void execute() throws Exception {
        String rulesDir = PathUtils.getSemgrepRulesPath();
        String sourcesDir = getSourcesDir();

        if (sourcesDir == null) {
            throw new RuntimeException("Decompiled sources directory not found");
        }

        log.info("[*] Running Semgrep with rules from: {}", rulesDir);
        log.info("[*] Scanning sources at: {}", sourcesDir);

        String result = CommandRunner.runQuiet(
                "semgrep --config " + rulesDir + " " + sourcesDir + " --json --no-git-ignore --quiet"
        );

        saveOutputToFile(result);
        log.info("[*] Semgrep scan completed successfully");
    }

    private String getSourcesDir() {
        String decompiledPath = PathUtils.getDecompiledApkPath();
        Path sources = Path.of(decompiledPath, "sources");
        if (Files.exists(sources)) {
            return sources.toString();
        }
        log.warn("[!] Semgrep requires JADX decompiled sources (sources/ directory)");
        return null;
    }

    private void saveOutputToFile(String output) {
        try {
            Path outputFile = Paths.get(PathUtils.getOutputPath(), OUTPUT_FILENAME);
            Files.createDirectories(outputFile.getParent());
            try (FileWriter writer = new FileWriter(outputFile.toFile())) {
                writer.write(output);
            }
            log.info("[*] Semgrep output saved to: {}", outputFile.toAbsolutePath());
        } catch (Exception e) {
            log.error("[!] Failed to save Semgrep output: {}", e.getMessage());
        }
    }
}
