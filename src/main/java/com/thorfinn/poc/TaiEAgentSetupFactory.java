package com.thorfinn.poc;

import com.phonepe.sentinelai.core.agent.AgentSetup;
import com.phonepe.sentinelai.core.model.ModelSettings;
import com.phonepe.sentinelai.core.utils.JsonUtils;
import com.phonepe.sentinelai.models.SimpleOpenAIModel;
import com.thorfinn.config.ToolsConfig;
import io.github.sashirestela.cleverclient.client.JavaHttpClientAdapter;
import io.github.sashirestela.cleverclient.client.RequestData;
import io.github.sashirestela.openai.SimpleOpenAI;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class TaiEAgentSetupFactory {

    private TaiEAgentSetupFactory() {
    }

    public static AgentSetup build(ToolsConfig toolsConfig) {
        if (toolsConfig == null) {
            throw new IllegalArgumentException("toolsConfig must not be null");
        }

        String modelName = requireNonBlank(toolsConfig.getLlmModel(), "llmModel");
        String baseUrl = requireNonBlank(toolsConfig.getLlmBaseUrl(), "llmBaseUrl");
        String apiKey = requireNonBlank(toolsConfig.getLlmApiKey(), "llmApiKey");

        var mapper = JsonUtils.createMapper();

        var simpleOpenAI = SimpleOpenAI.builder()
                .baseUrl(baseUrl)
                .apiKey(apiKey)
                .clientAdapter(new OBearerJavaHttpClientAdapter())
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

    private static final class OBearerJavaHttpClientAdapter extends JavaHttpClientAdapter {

        OBearerJavaHttpClientAdapter() {
            super(HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_1_1)
                    .connectTimeout(Duration.ofSeconds(30))
                    .build());
        }

        @Override
        protected Object send(RequestData requestData) {
            return super.send(rewriteAuthHeader(requestData));
        }

        @Override
        protected Object sendAsync(RequestData requestData) {
            return super.sendAsync(rewriteAuthHeader(requestData));
        }

        private RequestData rewriteAuthHeader(RequestData requestData) {
            List<String> headers = requestData.getHeaders();
            if (headers == null || headers.isEmpty()) {
                return requestData;
            }

            List<String> updated = new ArrayList<>(headers.size());
            for (int i = 0; i < headers.size(); i++) {
                String entry = headers.get(i);
                if (entry == null) {
                    updated.add(entry);
                    continue;
                }
                if (i % 2 == 0 && "authorization".equalsIgnoreCase(entry.trim()) && i + 1 < headers.size()) {
                    String value = headers.get(i + 1);
                    updated.add(entry);
                    if (value != null && value.toLowerCase(Locale.ROOT).startsWith("bearer ")) {
                        updated.add("O-Bearer " + value.substring("bearer ".length()));
                    } else {
                        updated.add(value);
                    }
                    i++;
                } else {
                    updated.add(entry);
                }
            }
            return requestData.withHeaders(updated);
        }
    }
}
