package com.thorfinn.llm;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class AntigravityClient implements LLMClient {

    private static final long TIMEOUT_SECONDS = 180;
    private static final long SHUTDOWN_GRACE_SECONDS = 5;

    private final String model;

    public AntigravityClient(String model) {
        this.model = model != null ? model.trim() : null;
    }

    @Override
    public String chat(String systemPrompt, String userPrompt) throws IOException {
        log.info("[*] Sending request to Antigravity CLI...");
        String prompt = buildPrompt(systemPrompt, userPrompt);

        List<String> command = buildCommand(prompt);

        ProcessBuilder processBuilder = new ProcessBuilder(command);
        Process process;
        try {
            process = processBuilder.start();
        } catch (IOException e) {
            throw new IOException(
                    "Antigravity CLI executable 'agy' was not found. "
                    + "Ensure 'agy' is installed and available in PATH.", e);
        }

        StringBuilder stdout = new StringBuilder();
        StringBuilder stderr = new StringBuilder();
        Thread stdoutReader = readStream(process.getInputStream(), stdout, "agy-stdout");
        Thread stderrReader = readStream(process.getErrorStream(), stderr, "agy-stderr");
        process.getOutputStream().close();

        int exitCode;
        try {
            if (!process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                terminate(process);
                joinReader(stdoutReader);
                joinReader(stderrReader);
                throw new IOException("Antigravity CLI timed out after " + TIMEOUT_SECONDS + " seconds");
            }
            exitCode = process.exitValue();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            terminate(process);
            joinReader(stdoutReader);
            joinReader(stderrReader);
            throw new IOException("Interrupted while waiting for Antigravity CLI", e);
        }

        joinReader(stdoutReader);
        joinReader(stderrReader);

        if (exitCode != 0) {
            String error = stderr.toString().trim();
            if (error.isEmpty()) {
                error = "No error details returned. Check that the Antigravity CLI is authenticated.";
            }
            throw new IOException("Antigravity CLI failed with exit code " + exitCode + ": " + error);
        }

        String response = stdout.toString().trim();
        if (response.isEmpty()) {
            throw new IOException("Antigravity CLI returned an empty response");
        }

        log.info("[*] Antigravity CLI response received ({} chars)", response.length());
        return response;
    }

    String buildPrompt(String systemPrompt, String userPrompt) {
        String system = systemPrompt == null ? "" : systemPrompt.trim();
        String user = userPrompt == null ? "" : userPrompt.trim();
        if (system.isEmpty()) {
            return user;
        }
        return "=== SYSTEM INSTRUCTIONS ===\n"
                + system
                + "\n\n=== USER PROMPT ===\n"
                + user;
    }

    List<String> buildCommand(String prompt) {
        List<String> command = new ArrayList<>();
        command.add("agy");
        command.add("-p");
        command.add(prompt);
        if (model != null && !model.isBlank()) {
            command.add("--model");
            command.add(model);
        }
        command.add("--output-format");
        command.add("text");
        return command;
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
                log.debug("Antigravity CLI stream closed: {}", e.getMessage());
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
            throw new IOException("Interrupted while reading Antigravity CLI output", e);
        }
    }
}
