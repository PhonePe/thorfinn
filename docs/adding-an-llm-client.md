# Adding an LLM Client

Thofinn supports multiple LLM providers including Gemini, OpenAI, and Anthropic. Adding a new client requires just implementing the `LLMClient` interface and registering it in `LLMUtils`. Each client has its own request, authorization token and response format, so adding a new providers requires you to handle these and rest is handled by the framework.

## 1. Create the client

Create the provider client under:

`src/main/java/com/thorfinn/llm/`

The class must implement `LLMClient`. Use the following method structure and implement each method according to the provider's API documentation:

```java
public class MyProviderClient implements LLMClient {

    public MyProviderClient(String apiKey, String model, String baseUrl) {
        // Configure the client with the API key, model, and base URL.
        // Include any additional provider-specific configuration here like additional headers, timeouts, etc.
    }

    @Override
    public String chat(String systemPrompt, String userPrompt) throws IOException {
        // Build the request body here including all parameters like system prompt, user prompt,authorization headers etc.
        // Send the request to the provider's chat endpoint and parse the response as per the provider's response format.
        // Return the content in required format back
    }
    

    private String extractText(JsonObject response) throws IOException {
        // Read the assistant text from the provider's response format.
        // Throw IOException if no usable text is present.
    }

    private void recordTokenUsage(JsonObject response) {
        // Extract token usage information from the provider's response.
        // Update the total token usage in the framework.
    }

    private String buildChatUrl() {
        // Build of chat URL in accordance with the provider's API documentation.
        // URL may require model in endpoint or as a query parameter, or may be fixed.
    }
}
```

Keep all provider-specific details inside this class, including:

- Endpoint and URL format
- Authentication headers
- Request payload
- Response parsing
- Token usage fields

## 2. Register the client

Open `src/main/java/com/thorfinn/utils/LLMUtils.java`.

Import the new client and add its provider name to the switch inside `create(...)`:

```java
public static LLMClient create(ToolsConfig toolsConfig) {
    //register the new provider here
    case "myprovider" -> new MyProviderClient(
            toolsConfig.getLlmApiKey(),
            toolsConfig.getLlmModel(),
            toolsConfig.getLlmBaseUrl()
    );
}
```

The switch value is what users set in `llmProvider`.

## 3. Configure the client

Set these chat fields in `config/config.yml`:

- `llmProvider`: provider name used in the `LLMUtils` switch
- `llmApiKey`: API key in the format required by the provider
- `llmModel`: provider model identifier
- `llmBaseUrl`: provider API base URL
