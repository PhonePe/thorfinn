package com.thorfinn.poc;

import com.phonepe.sentinelai.core.agent.AgentSetup;
import com.phonepe.sentinelai.core.model.ModelSettings;
import com.phonepe.sentinelai.core.utils.JsonUtils;
import com.phonepe.sentinelai.models.SimpleOpenAIModel;
import com.thorfinn.config.ToolsConfig;
import com.thorfinn.utils.LlmProviderSupport;
import io.github.sashirestela.cleverclient.client.JavaHttpClientAdapter;
import io.github.sashirestela.cleverclient.client.RequestData;
import io.github.sashirestela.openai.SimpleOpenAI;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class TaiEAgentSetupFactory {

    private TaiEAgentSetupFactory() {
    }

    public static AgentSetup build(ToolsConfig toolsConfig) {
        if (toolsConfig == null) {
            throw new IllegalArgumentException("toolsConfig must not be null");
        }

        LlmProviderSupport providerSupport = new LlmProviderSupport(toolsConfig);
        if (!providerSupport.supportsAgentMode()) {
            throw new IllegalArgumentException("TaiE agent mode is not supported for provider: " + providerSupport.provider());
        }

        String modelName = requireNonBlank(toolsConfig.getLlmModel(), "llmModel");
        String baseUrl = requireNonBlank(providerSupport.agentBaseUrl(), "agentBaseUrl");

        var mapper = JsonUtils.createMapper();

        var simpleOpenAI = SimpleOpenAI.builder()
                .baseUrl(baseUrl)
                .apiKey("placeholder")
                .clientAdapter(new ConfiguredHeadersHttpClientAdapter(providerSupport))
                .objectMapper(mapper)
                .build();

        var model = new SimpleOpenAIModel<>(modelName, simpleOpenAI, mapper);

        int maxToolResponsePercentage = toolsConfig.getTaiEAgentMaxToolResponsePercentage();
        if (maxToolResponsePercentage <= 0) {
            maxToolResponsePercentage = AgentSetup.DEFAULT_MAX_TOOL_RESPONSE_PERCENTAGE;
        }

        return AgentSetup.builder()
                .model(model)
                .mapper(mapper)
                .modelSettings(ModelSettings.builder()
                        .temperature(1f)
                        .timeout(Duration.ofSeconds(120))
                        .seed(1)
                        .build())
                .maxToolResponsePercentage(maxToolResponsePercentage)
                .build();
    }

    private static String requireNonBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }

    private static final class ConfiguredHeadersHttpClientAdapter extends JavaHttpClientAdapter {

        private final LlmProviderSupport providerSupport;

        ConfiguredHeadersHttpClientAdapter(LlmProviderSupport providerSupport) {
            super(HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_1_1)
                    .connectTimeout(Duration.ofSeconds(30))
                    .build());
            this.providerSupport = providerSupport;
        }

        @Override
        protected Object send(RequestData requestData) {
            return super.send(rewriteHeaders(requestData));
        }

        @Override
        protected Object sendAsync(RequestData requestData) {
            return super.sendAsync(rewriteHeaders(requestData));
        }

        private RequestData rewriteHeaders(RequestData requestData) {
            Map<String, String> desiredHeaders;
            try {
                desiredHeaders = providerSupport.requestHeaders();
            } catch (Exception e) {
                throw new IllegalStateException("Failed to resolve LLM headers for agent mode", e);
            }

            List<String> headers = requestData.getHeaders();
            List<String> source = headers == null ? List.of() : headers;

            List<String> updated = new ArrayList<>(Math.max(source.size(), desiredHeaders.size() * 2));
            Set<String> seenKeys = new HashSet<>();
            for (int i = 0; i < source.size(); i++) {
                String entry = source.get(i);
                if (entry == null) {
                    updated.add(entry);
                    continue;
                }

                if (i % 2 == 0 && i + 1 < source.size()) {
                    String key = entry.trim();
                    String matchedKey = findHeaderKey(desiredHeaders, key);
                    updated.add(entry);
                    if (matchedKey != null) {
                        updated.add(desiredHeaders.get(matchedKey));
                        seenKeys.add(matchedKey.toLowerCase());
                    } else {
                        updated.add(source.get(i + 1));
                    }
                    i++;
                } else {
                    updated.add(entry);
                }
            }

            for (Map.Entry<String, String> header : desiredHeaders.entrySet()) {
                if (!seenKeys.contains(header.getKey().toLowerCase())) {
                    updated.add(header.getKey());
                    updated.add(header.getValue());
                }
            }

            return requestData.withHeaders(updated);
        }

        private String findHeaderKey(Map<String, String> desiredHeaders, String actualKey) {
            for (String desired : desiredHeaders.keySet()) {
                if (desired.equalsIgnoreCase(actualKey)) {
                    return desired;
                }
            }
            return null;
        }
    }
}
