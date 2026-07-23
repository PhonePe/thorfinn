package com.thorfinn.utils;

import junit.framework.TestCase;

public class LLMClientTest extends TestCase {

    public void testExtractCopilotTextFromAssistantEvent() {
        String jsonl = "{\"type\":\"assistant.message\",\"data\":{\"content\":\"OK\"}}\n"
                + "{\"type\":\"assistant.turn_end\",\"data\":{\"message\":\"OK\"}}";

        assertEquals("OK\nOK", LLMClient.extractCopilotText(jsonl));
    }
}