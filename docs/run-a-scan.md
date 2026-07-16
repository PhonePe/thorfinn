## Usage

```
java -jar target/Thorfinn.jar <package-name> --config <path> [options]

Arguments:
  <package-name>              Android package name of the target app (must be installed on connected device)

Options:
  -c, --config <path>         Path to config.yml (required)
  -t, --time-limit <seconds>  Time limit for CPG/taint analysis
  -y, --auto-approve          Auto-approve every LLM-generated POC command without prompting
  -s, --skip-verify           Skip execution of all LLM-generated POC commands
  -h, --help                  Show this help message
```

Thorfinn requires a configuration file for LLM settings, taint rules, tool paths, and verification options. Pass it using the `--config` flag; relative paths are resolved from the current working directory.

> Note - LLM configuration is not mandatory

### Configuration

After setup, edit the config at `config/config.yml`:

```yaml
toolsConfig:
  decompilers: jadx
  analysisTools:
    - taie
    - semgrep
    - permissionChecker
    - truffleHog
  llmApiKey: Bearer YOUR_API_KEY # Add token with scheme e.g Bearer
  llmModel: gpt-4
  llmBaseUrl: https://api.openai.com/v1
  taiEAgentEnabled: false                 # flip to true if you reach input token limit in direct flow or else keep it false
  taiEAgentMaxToolResponsePercentage: 30 # Max context % for agent tool responses
  taiEMaxHeapGb: 0                        # Specify heap size here, defaults to 75% of available memory if 0

pathConfigs:
  baseDirectory: BASE_DIRECTORY_FOR_PROJECT
  decompiledApkPath: /resources/decompiled_apks/
  taiePath: /resources/tools/tai-e-all-0.5.4-SNAPSHOT.jar
  androidPlatformsPath: /resources/android-platforms/
  taieOutputPath: /resources/taie_output/
  taintConfigPath: /config/taint_config.yml
  permissionCheckerPath: /resources/tools/permissionChecker.py
  semgrepRulesPath: /resources/tools/semgrep-rules/
  outputPath: /resources/output/
```

#### Configuration Fields

**toolsConfig**

| Field | Description                                                                                                                                          |
|---|------------------------------------------------------------------------------------------------------------------------------------------------------|
| `decompilers` | Which decompiler to use. `jadx` produces Java source (recommended). `apktool` produces smali and decoded resources.                                  |
| `analysisTools` | List of tools to run. Remove a tool from the list to skip it. Order is preserved.                                                                    |
| `llmApiKey` | API key for the LLM provider. Required for false positive filtering and POC generation. Make sure you pass the key scheme as well e.g Bearer         |
| `llmModel` | Model identifier. Use any OpenAI-compatible model (e.g., `gpt-4`, `gpt-4o`).                                                                         |
| `llmBaseUrl` | Base URL of the LLM API endpoint. Works with any OpenAI-compatible API.                                                                              |
| `taiEAgentEnabled` | When `true`, the LLM can search the decompiled codebase on-demand for deeper analysis. When `false`, all code context is inlined in a single prompt. |
| `taiEAgentMaxToolResponsePercentage` | In agent mode, limits how much of the context window tool responses can consume.                                                                     |
| `taiEMaxHeapGb` | taiEMaxHeapGb is the maximum heap size for Tai-e analysis. If zero is will calculate the 75% of available memory and use that as the heap size.      |

**pathConfigs**

All paths are relative to the project root directory (where you run the JAR from). You typically don't need to change these unless you've rearranged the directory structure.
