package com.thorfinn.tools;

import com.thorfinn.utils.CommandRunner;
import com.thorfinn.utils.PathUtils;
import lombok.extern.slf4j.Slf4j;

import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Slf4j
public class PermissionChecker implements Tools {

    private static final String OUTPUT_FILENAME = "permission_checker_output.json";

    @Override
    public void execute() throws Exception {
        String manifestPath = findManifestPath();
        if (manifestPath == null) {
            throw new RuntimeException("AndroidManifest.xml not found in decompiled APK");
        }

        String scriptPath = PathUtils.getPermissionCheckerPath();
        log.info("[*] Running PermissionChecker: {} on {}", scriptPath, manifestPath);

        String result = CommandRunner.run(
                "python3 " + scriptPath + " " + manifestPath + " --format json"
        );

        saveOutputToFile(result);
        log.info("[*] PermissionChecker completed successfully");
    }

    private String findManifestPath() {
        String decompiledPath = PathUtils.getDecompiledApkPath();
        String[] candidates = {
                decompiledPath + "AndroidManifest.xml",
                decompiledPath + "resources/AndroidManifest.xml"
        };
        for (String path : candidates) {
            if (Files.exists(Path.of(path))) {
                return path;
            }
        }
        return null;
    }

    private void saveOutputToFile(String output) {
        try {
            Path outputFile = Paths.get(PathUtils.getOutputPath(), OUTPUT_FILENAME);
            Files.createDirectories(outputFile.getParent());
            try (FileWriter writer = new FileWriter(outputFile.toFile())) {
                writer.write(output);
            }
            log.info("[*] PermissionChecker output saved to: {}", outputFile.toAbsolutePath());
        } catch (Exception e) {
            log.error("[!] Failed to save PermissionChecker output: {}", e.getMessage());
        }
    }
}
