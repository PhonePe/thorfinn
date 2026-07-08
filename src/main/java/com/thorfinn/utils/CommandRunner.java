package com.thorfinn.utils;

import lombok.extern.slf4j.Slf4j;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Pattern;

@Slf4j
public class CommandRunner {
    private static final Pattern PACKAGE_NAME_PATTERN =
            Pattern.compile("^[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)+$");

    private CommandRunner() {

    }

    public static void validatePackageName(String packageName) {
        if (packageName == null || !PACKAGE_NAME_PATTERN.matcher(packageName).matches()) {
            throw new IllegalArgumentException(
                    "Invalid package name (must be a valid Android package identifier): " + packageName);
        }
    }

    public static String runArgs(String... args) throws Exception {
        List<String> command = Arrays.asList(args);
        log.info("[*] Running (args): {}", command);

        ProcessBuilder pb = new ProcessBuilder(command);
        Process process = pb.start();

        StringBuilder output = new StringBuilder();

        Thread stdoutThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    log.info("[stdout] {}", line);
                    synchronized (output) {
                        output.append(line).append("\n");
                    }
                }
            } catch (Exception e) {
                log.error("[!] Error reading stdout: {}", e.getMessage());
            }
        }, "cmd-stdout");

        Thread stderrThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    log.warn("[stderr] {}", line);
                    synchronized (output) {
                        output.append(line).append("\n");
                    }
                }
            } catch (Exception e) {
                log.error("[!] Error reading stderr: {}", e.getMessage());
            }
        }, "cmd-stderr");

        stdoutThread.start();
        stderrThread.start();

        int exitCode = process.waitFor();
        stdoutThread.join();
        stderrThread.join();

        String result = output.toString().trim();

        if (exitCode != 0) {
            log.error("[!] Command failed with exit code: {}", exitCode);
            throw new RuntimeException("Command failed (exit code " + exitCode + "): " + command + "\n" + result);
        }

        log.info("[*] Command exited with code: {}", exitCode);
        return result;
    }

    public static String runArgsQuiet(String... args) throws Exception {
        List<String> command = Arrays.asList(args);
        log.info("[*] Running (args-quiet): {}", command);

        ProcessBuilder pb = new ProcessBuilder(command);
        Process process = pb.start();

        StringBuilder output = new StringBuilder();

        Thread stdoutThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    synchronized (output) {
                        output.append(line).append("\n");
                    }
                }
            } catch (Exception e) {
                log.error("[!] Error reading stdout: {}", e.getMessage());
            }
        }, "cmd-stdout-quiet");

        Thread stderrThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                while (reader.readLine() != null) {
                }
            } catch (Exception e) {
            }
        }, "cmd-stderr-quiet");

        stdoutThread.start();
        stderrThread.start();

        int exitCode = process.waitFor();
        stdoutThread.join();
        stderrThread.join();

        String result = output.toString().trim();

        if (exitCode != 0) {
            log.warn("[!] Command exited with code: {} (may be non-fatal for some tools)", exitCode);
        } else {
            log.info("[*] Command completed successfully");
        }

        return result;
    }

    public static String run(String command) throws Exception {
        log.info("[*] Running: {}", command);

        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);

        Process process = pb.start();

        StringBuilder output = new StringBuilder();

        Thread stdoutThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    log.info("[stdout] {}", line);
                    synchronized (output) {
                        output.append(line).append("\n");
                    }
                }
            } catch (Exception e) {
                log.error("[!] Error reading stdout: {}", e.getMessage());
            }
        }, "cmd-stdout");

        Thread stderrThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    log.warn("[stderr] {}", line);
                    synchronized (output) {
                        output.append(line).append("\n");
                    }
                }
            } catch (Exception e) {
                log.error("[!] Error reading stderr: {}", e.getMessage());
            }
        }, "cmd-stderr");

        stdoutThread.start();
        stderrThread.start();

        int exitCode = process.waitFor();
        stdoutThread.join();
        stderrThread.join();

        String result = output.toString().trim();

        if (exitCode != 0) {
            log.error("[!] Command failed with exit code: {}", exitCode);
            throw new RuntimeException("Command failed (exit code " + exitCode + "): " + command + "\n" + result);
        }

        log.info("[*] Command exited with code: {}", exitCode);

        return result;
    }

    public static String runQuiet(String command) throws Exception {
        log.info("[*] Running (quiet): {}", command);

        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
        Process process = pb.start();

        StringBuilder output = new StringBuilder();

        Thread stdoutThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    synchronized (output) {
                        output.append(line).append("\n");
                    }
                }
            } catch (Exception e) {
                log.error("[!] Error reading stdout: {}", e.getMessage());
            }
        }, "cmd-stdout-quiet");

        Thread stderrThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {

                while (reader.readLine() != null) {
                }
            } catch (Exception e) {
            }
        }, "cmd-stderr-quiet");

        stdoutThread.start();
        stderrThread.start();

        int exitCode = process.waitFor();
        stdoutThread.join();
        stderrThread.join();

        String result = output.toString().trim();

        if (exitCode != 0) {
            log.warn("[!] Command exited with code: {} (may be non-fatal for some tools)", exitCode);
        } else {
            log.info("[*] Command completed successfully");
        }

        return result;
    }

    public static void deleteContentsOfFolder(Path folder) {
        if (!Files.exists(folder)) {
            log.info("[*] Folder does not exist, nothing to clean: {}", folder);
            return;
        }
        if (isProtectedDirectory(folder)) {
            throw new IllegalArgumentException(
                    "Refusing to delete contents of a protected/too-shallow directory: "
                            + folder.toAbsolutePath()
                            + ". Check the configured output path - it must point to a dedicated sub-directory.");
        }
        log.info("[*] Deleting contents of folder: {}", folder.toAbsolutePath());
        try (var walk = Files.walk(folder)) {
            walk.filter(p -> !p.equals(folder))
                    .sorted(Comparator.reverseOrder())
                    .forEach(p -> {
                        try {
                            Files.delete(p);
                        } catch (Exception e) {
                            log.warn("[!] Failed to delete: {}", p);
                        }
                    });
        } catch (Exception e) {
            log.error("[!] Failed to clean folder {}: {}", folder, e.getMessage());
        }
    }
    static boolean isProtectedDirectory(Path folder) {
        Path abs;
        try {
            // Resolve symlinks and normalize (e.g. collapse "/foo/.." → "/").
            abs = folder.toRealPath();
        } catch (Exception e) {
            abs = folder.toAbsolutePath().normalize();
        }

        // Filesystem root (e.g. "/") has zero name elements.
        if (abs.getNameCount() == 0 || abs.getParent() == null) {
            return true;
        }

        // Require at least two path segments so a single top-level dir (e.g. "/output",
        // "/Users") can never be wiped.
        if (abs.getNameCount() < 2) {
            return true;
        }

        // Never clean the user's home directory or the current working directory itself.
        Path home = Path.of(System.getProperty("user.home", "")).toAbsolutePath().normalize();
        Path cwd = Path.of(System.getProperty("user.dir", "")).toAbsolutePath().normalize();
        return abs.equals(home) || abs.equals(cwd);
    }
}
