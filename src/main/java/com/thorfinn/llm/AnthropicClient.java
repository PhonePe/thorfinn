package com.thorfinn.llm;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.thorfinn.utils.TokenUsageTracker;
import lombok.extern.slf4j.Slf4j;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

@Slf4j
public class AnthropicClient implements LLMClient {

    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final String MESSAGES_ENDPOINT = "/v1/messages";
    private static final String ANTHROPIC_VERSION = "2023-06-01";
    private static final int MAX_OUTPUT_TOKENS = 4096;

    private final String apiKey;
    private final String model;
    private final String baseUrl;
    private final OkHttpClient client;

    public AnthropicClient(String apiKey, String model, String baseUrl) {
        this.apiKey = apiKey;
        this.model = model;
        this.baseUrl = baseUrl;
        this.client = new OkHttpClient.Builder()
                .connectTimeout(60, TimeUnit.SECONDS)
                .readTimeout(120, TimeUnit.SECONDS)
                .writeTimeout(60, TimeUnit.SECONDS)
                .build();
    }

    @Override
    public String chat(String systemPrompt, String userPrompt) throws IOException {
        JsonObject requestBody = new JsonObject();
        requestBody.addProperty("model", model);
        requestBody.addProperty("max_tokens", MAX_OUTPUT_TOKENS);
        requestBody.addProperty("system", systemPrompt);

        JsonObject userMessage = new JsonObject();
        userMessage.addProperty("role", "user");
        userMessage.addProperty("content", userPrompt);

        JsonArray messages = new JsonArray();
        messages.add(userMessage);
        requestBody.add("messages", messages);

        Request request = new Request.Builder()
                .url(buildMessagesUrl())
                .addHeader("x-api-key", apiKey)
                .addHeader("anthropic-version", ANTHROPIC_VERSION)
                .addHeader("Content-Type", "application/json")
                .post(RequestBody.create(requestBody.toString(), JSON))
                .build();

        log.info("[*] Sending request to Anthropic...");

        try (Response response = client.newCall(request).execute()) {
            ResponseBody body = response.body();
            String responseBody = body != null ? body.string() : "";

            if (!response.isSuccessful()) {
                String errorBody = responseBody.isBlank() ? "No response body" : responseBody;
                log.error("[!] Anthropic API error ({}): {}", response.code(), errorBody);
                throw new IOException("Anthropic API request failed with code: " + response.code());
            }
            if (responseBody.isBlank()) {
                throw new IOException("Anthropic API returned empty response body");
            }

            try {
                JsonObject json = new Gson().fromJson(responseBody, JsonObject.class);
                logTokenUsage(json);

                String content = extractContent(json);
                log.info("[*] Anthropic response received ({} chars)", content.length());
                return content;
            } catch (RuntimeException e) {
                throw new IOException("Failed to parse Anthropic API response", e);
            }
        }
    }

    private String extractContent(JsonObject json) throws IOException {
        if (json == null || !json.has("content") || !json.get("content").isJsonArray()) {
            throw new IOException("Anthropic API response did not contain content");
        }

        StringBuilder result = new StringBuilder();
        for (JsonElement element : json.getAsJsonArray("content")) {
            if (!element.isJsonObject()) {
                continue;
            }

            JsonObject block = element.getAsJsonObject();
            if (!block.has("type") || !"text".equals(block.get("type").getAsString())) {
                continue;
            }
            if (!block.has("text") || block.get("text").isJsonNull()) {
                continue;
            }

            if (!result.isEmpty()) {
                result.append('\n');
            }
            result.append(block.get("text").getAsString());
        }

        if (result.isEmpty()) {
            throw new IOException("Anthropic API response did not contain text");
        }
        return result.toString();
    }

    private void logTokenUsage(JsonObject json) {
        if (json == null || !json.has("usage") || json.get("usage").isJsonNull()) {
            TokenUsageTracker.recordUnreported("chat");
            return;
        }

        JsonObject usage = json.getAsJsonObject("usage");
        TokenUsageTracker.record("chat",
                readLong(usage, "input_tokens"),
                readLong(usage, "output_tokens"),
                -1);
    }

    private long readLong(JsonObject object, String key) {
        return object.has(key) && !object.get(key).isJsonNull()
                ? object.get(key).getAsLong() : -1;
    }

    private String buildMessagesUrl() {
        String normalized = baseUrl == null ? "" : baseUrl.trim();
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized + MESSAGES_ENDPOINT;
    }
}

