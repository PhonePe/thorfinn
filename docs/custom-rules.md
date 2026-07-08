## Extending Thorfinn Rules

Thorfinn supports two types of rules:

1. **Taint analysis rules** define how attacker-controlled data enters the application, how it moves through the application, and which security-sensitive operations it should not reach.
2. **Pattern matching rules** identify unsafe Android code patterns, insecure configurations, and common implementation mistakes.

Use **taint analysis rules** when the vulnerability depends on data flow, such as an Intent extra reaching a WebView, file operation, ContentProvider, or component launch.

Use **pattern matching rules** when the issue can be identified from a specific code pattern, such as JavaScript being enabled in a WebView, dynamic receiver registration, or insecure API usage.

---

### Adding Taint Analysis Rules

Edit `config/taint_config.yml` to extend taint analysis coverage.

Taint rules define:

- **Sources**: where attacker-controlled data enters the application.
- **Sinks**: security-sensitive operations that should not receive attacker-controlled data.
- **Transfers**: how tainted data moves through helper methods, wrappers, builders, or framework APIs.

#### Add a Source

A source marks data as attacker-controlled.

```yaml
# Method return value is tainted
- { kind: call, method: "<com.lib.DeepLink: String getParam(String)>", index: result }

# Method parameter is tainted, such as a callback parameter in an exported component
- { kind: param, method: "<com.app.MyReceiver: void onReceive(Context,Intent)>", index: 1 }
```

#### Add a Sink

A sink marks a security-sensitive operation.

```yaml
# Argument at index 0 is the dangerous parameter
- { method: "<com.lib.Evaluator: void evaluate(String)>", index: 0 }
```

#### Add a Transfer

A transfer describes how taint propagates through a method.

```yaml
# Taint flows from argument 0 to the return value
- { method: "<com.lib.Wrapper: String wrap(String)>", from: 0, to: result }

# Taint flows from the base object to the return value
- { method: "<com.lib.Builder: Builder append(String)>", from: base, to: result }
```

The taint config uses Soot's method signature format:

```text
<FullClassName: ReturnType methodName(ParamTypes)>
```

---

### Adding Pattern Matching Rules

Create a `.yaml` file in:

```text
resources/tools/semgrep-rules/
```

Pattern matching rules are useful for checks that can be identified directly from code structure or API usage. These rules are picked up automatically on the next scan without code changes.

```yaml
rules:
  - id: webview-javascript-enabled
    patterns:
      - pattern: $SETTINGS.setJavaScriptEnabled(true);
    message: >
      WebView has JavaScript enabled. If attacker-controlled URLs
      can be loaded, this may lead to cross-site scripting.
    languages: [java]
    severity: WARNING
    metadata:
      category: security
      subcategory: webview
```

Rules follow the standard [Semgrep rule syntax](https://semgrep.dev/docs/writing-rules/overview).

For Android-specific patterns, target the decompiled Java source. Class names are deobfuscated by JADX where possible.