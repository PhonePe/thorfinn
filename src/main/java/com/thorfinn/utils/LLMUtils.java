package com.thorfinn.utils;

import java.util.Locale;

import com.thorfinn.config.ToolsConfig;
import com.thorfinn.llm.AnthropicClient;
import com.thorfinn.llm.GeminiClient;
import com.thorfinn.llm.GitHubCopilotClient;
import com.thorfinn.llm.LLMClient;
import com.thorfinn.llm.OpenAIClient;

public final class LLMUtils {

    private LLMUtils() {
    }

    public static LLMClient create(ToolsConfig toolsConfig) {
        if (toolsConfig == null) {
            throw new IllegalArgumentException("toolsConfig must not be null");
        }

        String provider = toolsConfig.getLlmProvider();
        if (provider == null || provider.isBlank()) {
            throw new IllegalArgumentException("llmProvider must not be blank");
        }

        return switch (provider.toLowerCase(Locale.ROOT)) {
            case "openai" ->
                new OpenAIClient(
                toolsConfig.getLlmApiKey(),
                toolsConfig.getLlmModel(),
                toolsConfig.getLlmBaseUrl()
                );
            case "gemini" ->
                new GeminiClient(
                toolsConfig.getLlmApiKey(),
                toolsConfig.getLlmModel(),
                toolsConfig.getLlmBaseUrl()
                );
            case "anthropic" ->
                new AnthropicClient(
                toolsConfig.getLlmApiKey(),
                toolsConfig.getLlmModel(),
                toolsConfig.getLlmBaseUrl()
                );
            case "copilot" ->
                new GitHubCopilotClient(
                toolsConfig.getLlmModel()
                );
            case "antigravity", "agy" ->
                new com.thorfinn.llm.AntigravityClient(
                toolsConfig.getLlmModel()
                );
            default ->
                throw new IllegalArgumentException("Unsupported LLM provider: " + provider);
        };
    }
}
