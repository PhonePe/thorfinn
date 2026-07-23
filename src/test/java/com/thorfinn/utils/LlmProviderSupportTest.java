package com.thorfinn.utils;

import com.thorfinn.config.ToolsConfig;
import junit.framework.TestCase;

import java.util.Map;

public class LlmProviderSupportTest extends TestCase {

    public void testBuildsOpenAiCompatibleUrls() {
        ToolsConfig config = new ToolsConfig();
        config.setLlmProvider("openai-compatible");
        config.setLlmApiKey("token-123");
        config.setLlmModel("gpt-4.1-mini");
        config.setLlmBaseUrl("https://api.openai.com");

        LlmProviderSupport support = new LlmProviderSupport(config);

        assertEquals("https://api.openai.com/v1/chat/completions", support.chatCompletionsUrl());
        assertEquals("https://api.openai.com", support.agentBaseUrl());
    }

    public void testNormalizesBearerHeaderForOpenAi() {
        ToolsConfig config = new ToolsConfig();
        config.setLlmProvider("openai-compatible");
        config.setLlmApiKey("openai_test");
        config.setLlmModel("gpt-4.1-mini");

        LlmProviderSupport support = new LlmProviderSupport(config);
        Map<String, String> headers = support.requestHeaders();

        assertEquals("Bearer openai_test", headers.get("Authorization"));
        assertEquals("application/json", headers.get("Content-Type"));
    }

    public void testCopilotCliProviderDisablesAgentMode() {
        ToolsConfig config = new ToolsConfig();
        config.setLlmProvider("github-copilot-cli");
        config.setLlmModel("gpt-5.4");

        LlmProviderSupport support = new LlmProviderSupport(config);

        assertTrue(support.isCliProvider());
        assertFalse(support.supportsAgentMode());
        assertEquals("copilot", support.cliCommand());
    }
}