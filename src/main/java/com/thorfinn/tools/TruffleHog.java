package com.thorfinn.tools;

import com.thorfinn.utils.CommandRunner;
import com.thorfinn.utils.PathUtils;
import lombok.extern.slf4j.Slf4j;

import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Slf4j
public class TruffleHog implements Tools {

    private static final String OUTPUT_FILENAME = "trufflehog_output.json";

    @Override
    public void execute() throws Exception {
        String decompiledPath = PathUtils.getDecompiledApkPath();
        if (!Files.exists(Path.of(decompiledPath))) {
            throw new RuntimeException("Decompiled APK directory not found: " + decompiledPath);
        }

        log.info("[*] Running TruffleHog on decompiled source: {}", decompiledPath);

        // grep exits 1 when no secrets are found - that's a valid "no findings" result,
        // not a failure. Append `|| true` so the pipeline returns 0 and we save empty output.
        String result = CommandRunner.run(
                "trufflehog filesystem " + decompiledPath + " --json --no-update 2>/dev/null | grep '\"SourceMetadata\"' || true"
        );

        saveOutputToFile(result);
        log.info("[*] TruffleHog completed successfully");
    }

    private void saveOutputToFile(String output) {
        try {
            Path outputFile = Paths.get(PathUtils.getOutputPath(), OUTPUT_FILENAME);
            Files.createDirectories(outputFile.getParent());
            try (FileWriter writer = new FileWriter(outputFile.toFile())) {
                writer.write(output);
            }
            log.info("[*] TruffleHog output saved to: {}", outputFile.toAbsolutePath());
        } catch (Exception e) {
            log.error("[!] Failed to save TruffleHog output: {}", e.getMessage());
        }
    }
}
