package com.thorfinn.utils;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import okhttp3.ResponseBody;

import java.io.IOException;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

@Slf4j
public class LLMClient {

    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final String CHAT_COMPLETIONS_ENDPOINT = "/v1/chat/completions";

    // Retry policy for transient failures (rate limits and upstream errors).
    // Findings are verified in a sequential loop, so once a per-minute token
    // budget is exhausted every subsequent call fail-fasts with 429 inside the
    // same minute. Backing off and retrying lets the budget window reset instead
    // of dropping findings as "LLM ERROR".
    private static final int MAX_ATTEMPTS = 5;
    private static final long INITIAL_BACKOFF_MS = 2_000L;
    private static final long MAX_BACKOFF_MS = 60_000L;
    private static final Set<Integer> RETRYABLE_STATUS = Set.of(429, 500, 502, 503, 504, 529);

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

        IOException lastError = null;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            log.info("[*] Sending request to LLM... (attempt {}/{})", attempt, MAX_ATTEMPTS);

            try (Response response = client.newCall(request).execute()) {
                if (response.isSuccessful()) {
                    return parseResponse(response);
                }

                int code = response.code();
                String errorBody = response.body() != null ? response.body().string() : "No response body";

                if (RETRYABLE_STATUS.contains(code) && attempt < MAX_ATTEMPTS) {
                    long delayMs = retryDelayMs(response, attempt);
                    log.warn("[!] LLM API returned {} (attempt {}/{}). Retrying in {} ms: {}",
                            code, attempt, MAX_ATTEMPTS, delayMs, errorBody);
                    sleep(delayMs);
                    continue;
                }

                log.error("[!] LLM API error ({}): {}", code, errorBody);
                throw new IOException("LLM API request failed with code: " + code);
            } catch (IOException e) {
                // Network-level failure (timeout, reset). Retry a few times before giving up.
                lastError = e;
                if (attempt >= MAX_ATTEMPTS) {
                    throw e;
                }
                long delayMs = backoffMs(attempt);
                log.warn("[!] LLM API request failed (attempt {}/{}): {}. Retrying in {} ms",
                        attempt, MAX_ATTEMPTS, e.getMessage(), delayMs);
                sleep(delayMs);
            }
        }

        throw lastError != null
                ? lastError
                : new IOException("LLM API request failed after " + MAX_ATTEMPTS + " attempts");
    }

    private String parseResponse(Response response) throws IOException {
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

    /**
     * Computes how long to wait before the next attempt. Prefers the server's
     * explicit hint ({@code Retry-After} in seconds or {@code retry-after-ms}),
     * otherwise falls back to exponential backoff with jitter.
     */
    private long retryDelayMs(Response response, int attempt) {
        Long serverHint = parseRetryAfter(response);
        if (serverHint != null) {
            return Math.min(serverHint, MAX_BACKOFF_MS);
        }
        return backoffMs(attempt);
    }

    private Long parseRetryAfter(Response response) {
        String retryAfterMs = response.header("retry-after-ms");
        if (retryAfterMs != null) {
            try {
                return (long) Math.ceil(Double.parseDouble(retryAfterMs.trim()));
            } catch (NumberFormatException ignored) {
                // fall through
            }
        }
        String retryAfter = response.header("Retry-After");
        if (retryAfter != null) {
            try {
                // OpenAI-compatible APIs send seconds (may be fractional).
                return (long) Math.ceil(Double.parseDouble(retryAfter.trim()) * 1000);
            } catch (NumberFormatException ignored) {
                // Non-numeric (HTTP-date) forms are not honoured; use backoff instead.
            }
        }
        return null;
    }

    private long backoffMs(int attempt) {
        long exp = INITIAL_BACKOFF_MS * (1L << (attempt - 1));
        long capped = Math.min(exp, MAX_BACKOFF_MS);
        long jitter = ThreadLocalRandom.current().nextLong(0, INITIAL_BACKOFF_MS);
        return Math.min(capped + jitter, MAX_BACKOFF_MS);
    }

    private void sleep(long millis) throws IOException {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while waiting to retry LLM request", e);
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
