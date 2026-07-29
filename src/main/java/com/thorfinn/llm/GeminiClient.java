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
public class GeminiClient implements LLMClient {

    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");

    private final String apiKey;
    private final String model;
    private final String baseUrl;
    private final OkHttpClient client;

    public GeminiClient(String apiKey, String model, String baseUrl) {
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

        JsonObject systemInstruction = new JsonObject();
        systemInstruction.add("parts", textParts(systemPrompt));
        requestBody.add("system_instruction", systemInstruction);

        JsonObject userContent = new JsonObject();
        userContent.addProperty("role", "user");
        userContent.add("parts", textParts(userPrompt));

        JsonArray contents = new JsonArray();
        contents.add(userContent);
        requestBody.add("contents", contents);

        Request request = new Request.Builder()
                .url(buildGenerateContentUrl())
                .addHeader("x-goog-api-key", apiKey)
                .addHeader("Content-Type", "application/json")
                .post(RequestBody.create(requestBody.toString(), JSON))
                .build();

        log.info("[*] Sending request to Gemini...");

        try (Response response = client.newCall(request).execute()) {
            ResponseBody body = response.body();
            String responseBody = body != null ? body.string() : "";

            if (!response.isSuccessful()) {
                String errorBody = responseBody.isBlank() ? "No response body" : responseBody;
                log.error("[!] Gemini API error ({}): {}", response.code(), errorBody);
                throw new IOException("Gemini API request failed with code: " + response.code());
            }
            if (responseBody.isBlank()) {
                throw new IOException("Gemini API returned empty response body");
            }

            try {
                JsonObject json = new Gson().fromJson(responseBody, JsonObject.class);
                logTokenUsage(json);

                String content = extractContent(json);
                log.info("[*] Gemini response received ({} chars)", content.length());
                return content;
            } catch (RuntimeException e) {
                throw new IOException("Failed to parse Gemini API response", e);
            }
        }
    }

    private JsonArray textParts(String text) {
        JsonObject part = new JsonObject();
        part.addProperty("text", text);

        JsonArray parts = new JsonArray();
        parts.add(part);
        return parts;
    }

    private String extractContent(JsonObject json) throws IOException {
        if (json == null || !json.has("candidates") || !json.get("candidates").isJsonArray()) {
            throw new IOException("Gemini API response did not contain candidates");
        }

        JsonArray candidates = json.getAsJsonArray("candidates");
        if (candidates.isEmpty()) {
            throw new IOException("Gemini API returned no candidates");
        }

        JsonObject candidate = candidates.get(0).getAsJsonObject();
        if (!candidate.has("content") || !candidate.get("content").isJsonObject()) {
            throw new IOException("Gemini API candidate did not contain content");
        }

        JsonObject content = candidate.getAsJsonObject("content");
        if (!content.has("parts") || !content.get("parts").isJsonArray()) {
            throw new IOException("Gemini API candidate content did not contain parts");
        }

        StringBuilder result = new StringBuilder();
        for (JsonElement element : content.getAsJsonArray("parts")) {
            if (!element.isJsonObject()) {
                continue;
            }
            JsonObject part = element.getAsJsonObject();
            if (!part.has("text") || part.get("text").isJsonNull()) {
                continue;
            }
            if (!result.isEmpty()) {
                result.append('\n');
            }
            result.append(part.get("text").getAsString());
        }

        if (result.isEmpty()) {
            throw new IOException("Gemini API candidate did not contain text");
        }
        return result.toString();
    }

    private void logTokenUsage(JsonObject json) {
        if (json == null || !json.has("usageMetadata") || json.get("usageMetadata").isJsonNull()) {
            TokenUsageTracker.recordUnreported("chat");
            return;
        }

        JsonObject usage = json.getAsJsonObject("usageMetadata");
        TokenUsageTracker.record("chat",
                readLong(usage, "promptTokenCount"),
                readLong(usage, "candidatesTokenCount"),
                readLong(usage, "totalTokenCount"));
    }

    private long readLong(JsonObject object, String key) {
        return object.has(key) && !object.get(key).isJsonNull()
                ? object.get(key).getAsLong() : -1;
    }

    private String buildGenerateContentUrl() {
        String normalizedBaseUrl = baseUrl == null ? "" : baseUrl.trim();
        while (normalizedBaseUrl.endsWith("/")) {
            normalizedBaseUrl = normalizedBaseUrl.substring(0, normalizedBaseUrl.length() - 1);
        }

        String normalizedModel = model == null ? "" : model.trim();
        if (normalizedModel.startsWith("models/")) {
            normalizedModel = normalizedModel.substring("models/".length());
        }

        return normalizedBaseUrl + "/v1beta/models/" + normalizedModel + ":generateContent";
    }
}


