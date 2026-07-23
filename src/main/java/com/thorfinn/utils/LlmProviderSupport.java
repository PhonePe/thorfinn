package com.thorfinn.utils;

import com.thorfinn.config.ToolsConfig;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

public final class LlmProviderSupport {

    public static final String PROVIDER_OPENAI_COMPATIBLE = "openai-compatible";
    public static final String PROVIDER_GITHUB_COPILOT_CLI = "github-copilot-cli";

    private static final String DEFAULT_OPENAI_BASE_URL = "https://api.openai.com";
    private static final String CHAT_COMPLETIONS_SUFFIX = "/chat/completions";
    private static final String OPENAI_V1_CHAT_COMPLETIONS_SUFFIX = "/v1/chat/completions";

    private final ToolsConfig toolsConfig;
    private final String provider;

    public LlmProviderSupport(ToolsConfig toolsConfig) {
        if (toolsConfig == null) {
            throw new IllegalArgumentException("toolsConfig must not be null");
        }
        this.toolsConfig = toolsConfig;
        this.provider = normalizeProvider(toolsConfig.getLlmProvider());
    }

    public String provider() {
        return provider;
    }

    public boolean isCliProvider() {
        return PROVIDER_GITHUB_COPILOT_CLI.equals(provider);
    }

    public boolean supportsAgentMode() {
        return PROVIDER_OPENAI_COMPATIBLE.equals(provider);
    }

    public String chatCompletionsUrl() {
        if (isCliProvider()) {
            throw new IllegalStateException("CLI provider does not expose an HTTP chat completions URL");
        }
        return buildOpenAICompatibleChatUrl(defaultIfBlank(toolsConfig.getLlmBaseUrl(), DEFAULT_OPENAI_BASE_URL));
    }

    public String agentBaseUrl() {
        if (!supportsAgentMode()) {
            throw new IllegalStateException("Agent mode is not supported for provider: " + provider);
        }
        return stripChatCompletionsSuffix(defaultIfBlank(toolsConfig.getLlmBaseUrl(), DEFAULT_OPENAI_BASE_URL));
    }

    public Map<String, String> requestHeaders() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");

        if (!isCliProvider()) {
            String token = requireNonBlank(toolsConfig.getLlmApiKey(), "llmApiKey");
            headers.put("Authorization", toBearer(token));
        }

        return headers;
    }

    public String cliCommand() {
        return defaultIfBlank(toolsConfig.getLlmCliCommand(), "copilot");
    }

    public static String normalizeProvider(String value) {
        if (value == null || value.isBlank()) {
            return PROVIDER_GITHUB_COPILOT_CLI;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "openai", "openai-compatible" -> PROVIDER_OPENAI_COMPATIBLE;
            case "github-copilot-cli", "github-copilot", "copilot-cli", "copilot" -> PROVIDER_GITHUB_COPILOT_CLI;
            default -> throw new IllegalArgumentException("Unsupported llmProvider: " + value
                    + ". Supported providers: openai-compatible, github-copilot-cli");
        };
    }

    private String buildOpenAICompatibleChatUrl(String configuredBaseUrl) {
        String normalized = stripTrailingSlash(configuredBaseUrl);
        if (normalized.endsWith(CHAT_COMPLETIONS_SUFFIX)) {
            return normalized;
        }
        if (normalized.endsWith("/v1")) {
            return normalized + CHAT_COMPLETIONS_SUFFIX;
        }
        return normalized + OPENAI_V1_CHAT_COMPLETIONS_SUFFIX;
    }

    private String stripChatCompletionsSuffix(String value) {
        String normalized = stripTrailingSlash(value);
        if (normalized.endsWith(CHAT_COMPLETIONS_SUFFIX)) {
            return normalized.substring(0, normalized.length() - CHAT_COMPLETIONS_SUFFIX.length());
        }
        return normalized;
    }

    private static String stripTrailingSlash(String value) {
        String normalized = value == null ? "" : value.trim();
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private static String defaultIfBlank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    private static String requireNonBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value.trim();
    }

    private static String toBearer(String rawToken) {
        String trimmed = rawToken.trim();
        return trimmed.regionMatches(true, 0, "Bearer ", 0, 7) ? trimmed : "Bearer " + trimmed;
    }
}
