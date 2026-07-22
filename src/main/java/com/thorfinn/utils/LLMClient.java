package com.thorfinn.utils;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import okhttp3.ResponseBody;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

@Slf4j
public class LLMClient {

    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final String CHAT_COMPLETIONS_ENDPOINT = "/v1/chat/completions";

    private final String apiKey;
    private final String model;
    private final String baseUrl;
    private final OkHttpClient client;

    public LLMClient(String apiKey, String model, String baseUrl) {
        this.apiKey = apiKey;
        this.model = model;
        this.baseUrl = baseUrl;
        this.client = new OkHttpClient.Builder()
                .connectTimeout(60, TimeUnit.SECONDS)
                .readTimeout(120, TimeUnit.SECONDS)
                .writeTimeout(60, TimeUnit.SECONDS)
                .build();
    }

    public String chat(String systemPrompt, String userPrompt) throws IOException {
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

        Request request = new Request.Builder()
                .url(buildChatCompletionsUrl(baseUrl))
                .addHeader("Authorization", apiKey)
                .addHeader("Content-Type", "application/json")
                .post(RequestBody.create(requestBody.toString(), JSON))
                .build();

        log.info("[*] Sending request to LLM...");

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
            String content = json.getAsJsonArray("choices")
                    .get(0).getAsJsonObject()
                    .getAsJsonObject("message")
                    .get("content").getAsString();

            logTokenUsage(json);
            log.info("[*] LLM response received ({} chars)", content.length());
            return content;
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

    private String buildChatCompletionsUrl(String configuredBaseUrl) {
        String normalized = configuredBaseUrl == null ? "" : configuredBaseUrl.trim();
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized + CHAT_COMPLETIONS_ENDPOINT;
    }
}
