package com.thorfinn.llm;

import java.io.IOException;

public interface LLMClient {

    String chat(String systemPrompt, String userPrompt) throws IOException;
}

