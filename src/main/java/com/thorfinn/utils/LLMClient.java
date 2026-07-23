package com.thorfinn.utils;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.thorfinn.config.ToolsConfig;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import okhttp3.ResponseBody;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
public class LLMClient {

    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");

    private final String model;
    private final OkHttpClient client;
    private final LlmProviderSupport providerSupport;

    public LLMClient(String apiKey, String model, String baseUrl) {
        ToolsConfig toolsConfig = new ToolsConfig();
        toolsConfig.setLlmApiKey(apiKey);
        toolsConfig.setLlmModel(model);
        toolsConfig.setLlmBaseUrl(baseUrl);
        toolsConfig.setLlmProvider(LlmProviderSupport.PROVIDER_OPENAI_COMPATIBLE);
        this.providerSupport = new LlmProviderSupport(toolsConfig);
        this.model = model;
        this.client = new OkHttpClient.Builder()
                .connectTimeout(60, TimeUnit.SECONDS)
                .readTimeout(120, TimeUnit.SECONDS)
                .writeTimeout(60, TimeUnit.SECONDS)
                .build();
    }

    public LLMClient(ToolsConfig toolsConfig) {
        this.providerSupport = new LlmProviderSupport(toolsConfig);
        this.model = requireNonBlank(toolsConfig.getLlmModel(), "llmModel");
        this.client = new OkHttpClient.Builder()
                .connectTimeout(60, TimeUnit.SECONDS)
                .readTimeout(120, TimeUnit.SECONDS)
                .writeTimeout(60, TimeUnit.SECONDS)
                .build();
    }

    public String chat(String systemPrompt, String userPrompt) throws IOException {
        if (providerSupport.isCliProvider()) {
            return chatViaCopilotCli(systemPrompt, userPrompt);
        }

        JsonObject requestBody = new JsonObject();
        requestBody.addProperty("model", model);

        JsonArray messages = new JsonArray();

        JsonObject systemMessage = new JsonObject();
        systemMessage.addProperty("role", "system");
        systemMessage.addProperty("content", systemPrompt);
        messages.add(systemMessage);

        JsonObject userMessage = new JsonObject();
        userMessage.addProperty("role", "user");
        userMessage.addProperty("content", userPrompt);
        messages.add(userMessage);

        requestBody.add("messages", messages);

        Request.Builder requestBuilder = new Request.Builder()
            .url(providerSupport.chatCompletionsUrl())
            .post(RequestBody.create(requestBody.toString(), JSON));

        for (Map.Entry<String, String> header : providerSupport.requestHeaders().entrySet()) {
            requestBuilder.addHeader(header.getKey(), header.getValue());
        }

        Request request = requestBuilder.build();

        log.info("[*] Sending request to LLM provider={}...", providerSupport.provider());

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                String errorBody = response.body() != null ? response.body().string() : "No response body";
                log.error("[!] LLM API error ({}): {}", response.code(), errorBody);
                throw new IOException("LLM API request failed with code: " + response.code());
            }

            ResponseBody body = response.body();
            if (body == null) {
                throw new IOException("LLM API returned empty response body");
            }
            String responseBody = body.string();
            JsonObject json = new Gson().fromJson(responseBody, JsonObject.class);
            String content = extractContent(json);

            logTokenUsage(json);
            log.info("[*] LLM response received ({} chars)", content.length());
            return content;
        }
    }

    static String extractCopilotText(String output) {
        if (output == null || output.isBlank()) {
            return "";
        }

        List<String> chunks = new ArrayList<>();
        String error = null;
        for (String line : output.split("\\R")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || !trimmed.startsWith("{")) {
                continue;
            }

            JsonObject event;
            try {
                event = new Gson().fromJson(trimmed, JsonObject.class);
            } catch (Exception ignored) {
                continue;
            }

            if (event == null || !event.has("type")) {
                continue;
            }

            String type = event.get("type").getAsString();
            if (type.toLowerCase().contains("error")) {
                error = collectText(event.get("data"));
                if (error == null || error.isBlank()) {
                    error = collectText(event);
                }
                continue;
            }

            if (!type.startsWith("assistant.")) {
                continue;
            }

            String text = collectText(event.get("data"));
            if ((text == null || text.isBlank()) && event.has("message")) {
                text = collectText(event.get("message"));
            }
            if (text != null && !text.isBlank()) {
                chunks.add(text.trim());
            }
        }

        String joined = String.join("\n", chunks).trim();
        if (!joined.isEmpty()) {
            return joined;
        }
        if (error != null && !error.isBlank()) {
            throw new IllegalStateException("GitHub Copilot CLI returned an error: " + error.trim());
        }
        return "";
    }

    private String chatViaCopilotCli(String systemPrompt, String userPrompt) throws IOException {
        String prompt = buildCopilotCliPrompt(systemPrompt, userPrompt);
        String textCommand = buildCopilotCliCommandString(
            "-p",
            prompt,
            "--model",
            model,
            "-s",
            "--output-format",
            "text",
            "--stream",
            "off",
            "--no-custom-instructions",
            "--no-auto-update"
        );

        try {
            String textOutput = CommandRunner.runQuiet(textCommand);
            if (textOutput != null && !textOutput.isBlank()) {
                log.info("[*] LLM response received from GitHub Copilot CLI ({} chars)", textOutput.trim().length());
                TokenUsageTracker.recordUnreported("chat-cli");
                return textOutput.trim();
            }

            String jsonOutput = CommandRunner.run(
                buildCopilotCliCommandString(
                    "-p",
                    prompt,
                    "--model",
                    model,
                    "--output-format",
                    "json",
                    "--stream",
                    "off",
                    "--no-custom-instructions",
                    "--no-auto-update"
                    )
            );
            String parsed = extractCopilotText(jsonOutput);
            if (parsed.isBlank()) {
                throw new IOException("GitHub Copilot CLI produced no assistant output");
            }
            log.info("[*] LLM response received from GitHub Copilot CLI JSON stream ({} chars)", parsed.length());
            TokenUsageTracker.recordUnreported("chat-cli");
            return parsed;
        } catch (Exception e) {
            throw new IOException("GitHub Copilot CLI request failed", e);
        }
    }

    private void logTokenUsage(JsonObject json) {
        if (json == null || !json.has("usage") || json.get("usage").isJsonNull()) {
            TokenUsageTracker.recordUnreported("chat");
            return;
        }
        JsonObject usage = json.getAsJsonObject("usage");
        TokenUsageTracker.record("chat",
                readLong(usage, "prompt_tokens"),
                readLong(usage, "completion_tokens"),
                readLong(usage, "total_tokens"));
    }

    private long readLong(JsonObject obj, String key) {
        return obj.has(key) && !obj.get(key).isJsonNull()
                ? obj.get(key).getAsLong() : -1;
    }

    private String extractContent(JsonObject json) throws IOException {
        if (json == null || !json.has("choices") || !json.get("choices").isJsonArray()
                || json.getAsJsonArray("choices").isEmpty()) {
            throw new IOException("LLM API response did not contain choices");
        }

        JsonObject firstChoice = json.getAsJsonArray("choices").get(0).getAsJsonObject();
        if (!firstChoice.has("message") || !firstChoice.get("message").isJsonObject()) {
            throw new IOException("LLM API response did not contain a message payload");
        }

        JsonObject message = firstChoice.getAsJsonObject("message");
        if (!message.has("content") || message.get("content").isJsonNull()) {
            return "";
        }

        return collectText(message.get("content"));
    }

    private static String collectText(JsonElement element) {
        if (element == null || element.isJsonNull()) {
            return "";
        }
        if (element.isJsonPrimitive()) {
            return element.getAsString();
        }
        if (element.isJsonArray()) {
            List<String> parts = new ArrayList<>();
            for (JsonElement item : element.getAsJsonArray()) {
                String text = collectText(item);
                if (text != null && !text.isBlank()) {
                    parts.add(text);
                }
            }
            return String.join("\n", parts).trim();
        }
        if (element.isJsonObject()) {
            JsonObject obj = element.getAsJsonObject();
            if (obj.has("text") && !obj.get("text").isJsonNull()) {
                return obj.get("text").getAsString();
            }
            if (obj.has("content") && !obj.get("content").isJsonNull()) {
                String text = collectText(obj.get("content"));
                if (!text.isBlank()) {
                    return text;
                }
            }
            if (obj.has("message") && !obj.get("message").isJsonNull()) {
                String text = collectText(obj.get("message"));
                if (!text.isBlank()) {
                    return text;
                }
            }
            if (obj.has("delta") && !obj.get("delta").isJsonNull()) {
                String text = collectText(obj.get("delta"));
                if (!text.isBlank()) {
                    return text;
                }
            }
        }
        return "";
    }

    private String buildCopilotCliPrompt(String systemPrompt, String userPrompt) {
        return normalizeWhitespace(
            "You are being used as a non-interactive text backend for Thorfinn. "
                + "Do not modify files or run tools. Return only the final answer. "
                + "System prompt: " + systemPrompt + " User prompt: " + userPrompt
        );
    }

    private String buildCopilotCliCommandString(String... args) {
        List<String> command = new ArrayList<>();
        String cliCommand = providerSupport.cliCommand();
        command.add(shellQuote(cliCommand));
        if ("gh".equals(cliCommand) || cliCommand.endsWith("/gh")) {
            command.add("copilot");
            command.add("--");
        }
        for (String arg : args) {
            command.add(shellQuote(arg));
        }
        return String.join(" ", command);
    }

    private static String requireNonBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value.trim();
    }

    private static String normalizeWhitespace(String value) {
        return value == null ? "" : value.replaceAll("\\s+", " ").trim();
    }

    private static String shellQuote(String value) {
        if (value == null) {
            return "''";
        }
        return "'" + value.replace("'", "'\"'\"'") + "'";
    }
}
