package com.thorfinn.llm;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.thorfinn.utils.TokenUsageTracker;
import lombok.extern.slf4j.Slf4j;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Slf4j
public class GitHubCopilotClient implements LLMClient {

    private static final long TIMEOUT_SECONDS = 120;
    private static final long SHUTDOWN_GRACE_SECONDS = 5;

    private final String model;

    public GitHubCopilotClient(String model) {
        if (model == null || model.isBlank()) {
            throw new IllegalArgumentException("llmModel must not be blank when llmProvider is copilot");
        }
        this.model = model.trim();
    }

    @Override
    public String chat(String systemPrompt, String userPrompt) throws IOException {
        Path telemetryDirectory = createTelemetryDirectory();
        Path telemetryFile = telemetryDirectory != null
                ? telemetryDirectory.resolve("usage.jsonl") : null;
        log.info("[*] Sending request to Github Copilot...");
        try {
            String prompt = buildPrompt(systemPrompt, userPrompt);
            List<String> command = List.of(
                    "copilot",
                    "--prompt", prompt,
                    "--model", model,
                    "--silent",
                    "--no-color",
                    "--available-tools="
            );

            ProcessBuilder processBuilder = new ProcessBuilder(command);
            if (telemetryFile != null) {
                processBuilder.environment().put(
                        "COPILOT_OTEL_FILE_EXPORTER_PATH", telemetryFile.toString());
                processBuilder.environment().put(
                        "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", "false");
            }

            Process process;
            try {
                process = processBuilder.start();
            } catch (IOException e) {
                throw new IOException(
                        "GitHub Copilot CLI executable 'copilot' was not found. "
                                + "Install it and authenticate before using llmProvider: copilot.", e);
            }

            StringBuilder stdout = new StringBuilder();
            StringBuilder stderr = new StringBuilder();
            Thread stdoutReader = readStream(process.getInputStream(), stdout, "copilot-stdout");
            Thread stderrReader = readStream(process.getErrorStream(), stderr, "copilot-stderr");
            process.getOutputStream().close();

            int exitCode;
            try {
                if (!process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    terminate(process);
                    joinReader(stdoutReader);
                    joinReader(stderrReader);
                    throw new IOException("GitHub Copilot CLI timed out after " + TIMEOUT_SECONDS + " seconds");
                }
                exitCode = process.exitValue();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                terminate(process);
                joinReader(stdoutReader);
                joinReader(stderrReader);
                throw new IOException("Interrupted while waiting for GitHub Copilot CLI", e);
            }

            joinReader(stdoutReader);
            joinReader(stderrReader);

            if (exitCode != 0) {
                String error = stderr.toString().trim();
                if (error.isEmpty()) {
                    error = "No error details were returned. Check that the CLI is authenticated and the model is available.";
                }
                throw new IOException("GitHub Copilot CLI failed with exit code " + exitCode + ": " + error);
            }

            String response = stdout.toString().trim();
            if (response.isEmpty()) {
                throw new IOException("GitHub Copilot CLI returned an empty response");
            }

            recordTokenUsage(telemetryFile);
            log.info("[*] GitHub Copilot response received ({} chars)", response.length());
            return response;
        } finally {
            deleteTelemetryFiles(telemetryDirectory, telemetryFile);
        }
    }

    private Path createTelemetryDirectory() {
        try {
            return Files.createTempDirectory("thorfinn-copilot-");
        } catch (IOException e) {
            log.warn("[!] Could not create Copilot telemetry directory: {}", e.getMessage());
            return null;
        }
    }

    private void recordTokenUsage(Path telemetryFile) {
        TokenUsage usage = readTokenUsage(telemetryFile);
        if (usage == null) {
            TokenUsageTracker.recordUnreported("chat");
            return;
        }

        TokenUsageTracker.record("chat", usage.inputTokens(), usage.outputTokens(),
                usage.inputTokens() + usage.outputTokens());
    }

    private TokenUsage readTokenUsage(Path telemetryFile) {
        if (telemetryFile == null || !Files.isRegularFile(telemetryFile)) {
            return null;
        }

        long inputTokens = 0;
        long outputTokens = 0;
        boolean foundChatSpan = false;

        try (BufferedReader reader = Files.newBufferedReader(telemetryFile, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                JsonObject record;
                try {
                    record = JsonParser.parseString(line).getAsJsonObject();
                } catch (RuntimeException e) {
                    continue;
                }

                if (!record.has("name") || !record.get("name").getAsString().startsWith("chat ")
                        || !record.has("attributes") || !record.get("attributes").isJsonObject()) {
                    continue;
                }

                JsonObject attributes = record.getAsJsonObject("attributes");
                Long spanInput = readLong(attributes, "gen_ai.usage.input_tokens");
                Long spanOutput = readLong(attributes, "gen_ai.usage.output_tokens");
                if (spanInput == null || spanOutput == null) {
                    continue;
                }

                inputTokens += spanInput;
                outputTokens += spanOutput;
                foundChatSpan = true;
            }
        } catch (IOException e) {
            log.warn("[!] Could not read Copilot token usage: {}", e.getMessage());
            return null;
        }

        return foundChatSpan ? new TokenUsage(inputTokens, outputTokens) : null;
    }

    private Long readLong(JsonObject object, String key) {
        if (!object.has(key) || object.get(key).isJsonNull()) {
            return null;
        }
        try {
            return object.get(key).getAsLong();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private void deleteTelemetryFiles(Path telemetryDirectory, Path telemetryFile) {
        try {
            if (telemetryFile != null) {
                Files.deleteIfExists(telemetryFile);
            }
            if (telemetryDirectory != null) {
                Files.deleteIfExists(telemetryDirectory);
            }
        } catch (IOException e) {
            log.debug("Could not delete Copilot telemetry files: {}", e.getMessage());
        }
    }

    private record TokenUsage(long inputTokens, long outputTokens) {
    }

    private String buildPrompt(String systemPrompt, String userPrompt) {
        String system = systemPrompt == null ? "" : systemPrompt;
        String user = userPrompt == null ? "" : userPrompt;
        return "=== SYSTEM INSTRUCTIONS ===\n"
                + system
                + "\n\n=== USER PROMPT ===\n"
                + user;
    }

    private Thread readStream(InputStream stream, StringBuilder output, String threadName) {
        Thread readerThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(stream, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append('\n');
                }
            } catch (IOException e) {
                log.debug("GitHub Copilot stream closed: {}", e.getMessage());
            }
        }, threadName);
        readerThread.setDaemon(true);
        readerThread.start();
        return readerThread;
    }

    private void terminate(Process process) {
        process.destroy();
        try {
            if (!process.waitFor(SHUTDOWN_GRACE_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
        }
    }

    private void joinReader(Thread readerThread) throws IOException {
        try {
            readerThread.join(TimeUnit.SECONDS.toMillis(SHUTDOWN_GRACE_SECONDS));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while reading GitHub Copilot CLI output", e);
        }
    }
}
