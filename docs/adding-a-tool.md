
Thorfinn's pipeline is built on three simple interfaces. Every tool in the framework - Tai-e, Semgrep, TruffleHog, PermissionChecker - follows the same pattern. Adding a new tool means implementing these three interfaces and registering it in the config.

#### Interface 1: `Tools` - Execute the tool

This interface runs your tool against the decompiled APK and saves the raw output.

```java
public interface Tools {
    void execute() throws Exception;
}
```

Example implementation:

```java
public class MyTool implements Tools {

    @Override
    public void execute() throws Exception {
        String decompiledPath = PathUtils.getDecompiledApkPath();

        // Run your tool and capture output
        String result = CommandRunner.run(
            "my-tool --scan " + decompiledPath + " --format json"
        );

        // Save output to the standard output directory
        Path outputFile = Paths.get(PathUtils.getOutputPath(), "my_tool_output.json");
        Files.createDirectories(outputFile.getParent());
        Files.writeString(outputFile, result);
    }
}
```

#### Interface 2: `Parsers<T>` - Parse raw output

This interface reads the raw output from your tool and converts it into structured data that the POC generator can work with.

```java
public interface Parsers<T> {
    T parse() throws Exception;
}
```

Example implementation:

```java
public class MyToolParser implements Parsers<List<MyToolResult>> {

    @Override
    public List<MyToolResult> parse() throws Exception {
        Path outputFile = Paths.get(PathUtils.getOutputPath(), "my_tool_output.json");
        String content = Files.readString(outputFile);
        // Parse JSON into structured results
        return new Gson().fromJson(content, new TypeToken<List<MyToolResult>>(){}.getType());
    }
}
```

#### Interface 3: `poc` - Generate findings

This interface takes the parsed results, optionally uses the LLM for false positive filtering, and produces a list of `Finding` objects with POC commands.

```java
public interface poc {
    List<Finding> generateFindings() throws Exception;
}
```

Example implementation:

```java
public class MyToolPOC implements poc {

    @Override
    public List<Finding> generateFindings() throws Exception {
        MyToolParser parser = new MyToolParser();
        List<MyToolResult> results = parser.parse();

        List<Finding> findings = new ArrayList<>();
        for (MyToolResult result : results) {
            // Optionally use LLMClient to validate the finding
            // and generate a POC command

            findings.add(Finding.builder()
                .tool("myTool")
                .truePositive(true)
                .sourceFile(result.getFile())
                .sinkFile(result.getFile())
                .vulnerabilityClass("My Vulnerability Type")
                .analysis("Description of the issue")
                .poc("adb shell \"am start -n com.target/.Activity\"")
                .build());
        }
        return findings;
    }
}
```

#### Register the tool

**Step 1:** Add the tool name to `config/config.yml`:

```yaml
toolsConfig:
  analysisTools:
    - taie
    - semgrep
    - permissionChecker
    - truffleHog
    - myTool              # Your new tool
```

**Step 2:** Add cases for your tool in `Orchestrator.java`:

```java
// In executeTools()
case "myTool" -> {
    Tools myTool = new MyTool();
    myTool.execute();
}

// In generatePOCs()
case "myTool" -> {
    poc myToolPOC = new MyToolPOC();
    allFindings.addAll(myToolPOC.generateFindings());
}
```

That's it. Your tool will now run as part of the pipeline, its findings will be verified on the device, and they'll appear in the HTML report.

