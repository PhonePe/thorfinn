package com.thorfinn.poc;

import com.thorfinn.config.ConfigContext;
import com.thorfinn.config.ToolsConfig;
import com.thorfinn.models.Finding;
import com.thorfinn.models.TaiEAgentModels;
import com.thorfinn.models.TaiEResult;
import com.thorfinn.models.TaiEResult.TaintFlowInfo;
import com.thorfinn.parsers.TaiEParser;
import com.thorfinn.utils.LLMClient;
import com.thorfinn.utils.PathUtils;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Slf4j
public class TaiEPOC implements poc {

    private TaiECodeLookupService codeLookupService;

    private static final String SYSTEM_PROMPT_INTRO_SMALI = """
            You are an expert Android security researcher analyzing taint flow findings from taie/Tai-e. You will receive:
            1. A taint flow finding (source → sink) with the full flow path.
            2. Smali code of the source, sink, and any intermediate classes.
            3. AndroidManifest.xml with component declarations, exports, and intent filters.
            """;

    private static final String SYSTEM_PROMPT_INTRO_JAVA = """
            You are an expert Android security researcher analyzing taint flow findings from taie/Tai-e. You will receive:
            1. A taint flow finding (source → sink) with the full flow path.
            2. Decompiled Java source of the source, sink, and any intermediate classes.
            3. AndroidManifest.xml with component declarations, exports, and intent filters.
            """;

    private static final String SYSTEM_PROMPT_BODY = """
            IMPORTANT RULES:
            - Analyze each finding INDIVIDUALLY. Never chain multiple findings. Base your verdict ONLY on the CURRENT code, flow, files involved, dont involve files that are not in the flow since that flow will be part of other finding. Do NOT consider hypothetical fixes.
            - Only mark TRUE POSITIVE if THIS exact source-sink pair is exploitable as-is. A different exploitable path in the same code does not make the given flow a TP.
            - Lack of sanitization in the current code = TRUE POSITIVE regardless of whether it could be added later.
            
            VULNERABILITY REFERENCE KNOWLEDGE:
            
            1. WebView Vulnerability: Attacker-controlled data (Intent extras, deep links) flows into WebView.loadUrl(), loadData(), or evaluateJavascript() without validation.
            
            2. Third-Party Package Context Code Execution: App scans installed packages (getInstalledPackages/getInstalledApplications), matches by weak criteria (package name prefix/suffix/contains), calls createPackageContext(pkg, CONTEXT_INCLUDE_CODE | CONTEXT_IGNORE_SECURITY), then loads and invokes classes via reflection with no signature verification (checkSignatures()).
            
            3. Intent Redirection: Exported component extracts a nested Intent and passes it to a component launcher, allowing attacker to reach non-exported components.
               EXTRACTION PATTERNS: getParcelableExtra(), getExtras().get/getParcelable(), Intent.parseUri(stringExtra), getParcelableArrayExtra()[0], getParcelableArrayListExtra().get(0), Fragment.getArguments().getParcelable()
               SINKS: startActivity(), startActivityForResult(), startService(), sendBroadcast(), sendOrderedBroadcast(), setResult(RESULT_OK, intent), startActivities()
               NOTE - setResult: Attacker can set FLAG_GRANT_READ/WRITE_URI_PERMISSION on an internal provider URI; when victim activity returns via setResult(), attacker gains URI grant access to the victim's protected content providers.
               TRUE POSITIVE if: source exported AND nested Intent extracted via above patterns AND passed to sink without component validation.
               FALSE POSITIVE if: source not exported OR component/package validated before use OR app builds a fresh Intent(this, Target.class) using only data from extras.
            
            4. Implicit Intent Interception: Intent created via new Intent("ACTION") or new Intent("ACTION", uri) (no explicit component) reaches startActivity/startActivityForResult/sendBroadcast/startService/bindService/PendingIntent. Attacker app with matching intent-filter intercepts it.
               TRUE POSITIVE if: Intent stays implicit to the sink (no setComponent/setClass/setClassName/setPackage between constructor and sink) AND sent where external apps can receive it AND carries sensitive data or performs a sensitive operation.
               FALSE POSITIVE if: explicit component set before sink OR LocalBroadcastManager used OR signature-level permission on sendBroadcast OR FLAG_IMMUTABLE on PendingIntent OR safe system action with no sensitive extras.
            
            5. Path Traversal in Content Providers: Exported ContentProvider uses getLastPathSegment()/getPathSegments()/getPath() (which auto-URL-decode: ..%2F→../) in file path construction without sanitizing "..".
               TRUE POSITIVE if: ContentProvider exported AND path segment used directly in file construction AND no ".." check or canonicalPath validation.
               FALSE POSITIVE if: not exported OR canonicalPath checked against base dir OR ".." rejected OR path comes from DB lookup (not URI).
            
            6. Content Provider Proxy / URI Forwarding: Exported component forwards attacker-controlled URI to ContentResolver.query/insert/update/delete/openFile/openInputStream/openOutputStream.
               PATTERNS: Uri.parse(uri.getQueryParameter("uri")) → query(); getIntent().getStringExtra("target") → openInputStream(Uri.parse(target))
               TRUE POSITIVE if: source exported AND attacker URI forwarded to ContentResolver AND no authority/scheme validation.
               FALSE POSITIVE if: not exported OR URI authority/scheme validated against allowlist OR URI is hardcoded.
               IMPORTANT: If URI reaches a write-capable sink (openOutputStream, openFileDescriptor "w/rw/wt") and data is written, classify as Arbitrary File Write.
            
            7. Arbitrary File Write: Exported component accepts attacker-controlled Uri (via Intent extra, Bundle.getParcelable(), Intent.getData()) and opens it for WRITING using the app's own identity/permissions.
               WRITE-CAPABLE SINKS: openOutputStream(uri), openOutputStream(uri, mode), openFileDescriptor(uri, "w"/"rw"/"wt"), openAssetFileDescriptor(uri, "w").
               TRUE POSITIVE if: source exported AND attacker controls Uri target AND write-capable sink used AND no Uri allowlist/permission check.
               FALSE POSITIVE if: not exported OR Uri app-created OR read-only sink OR strict Uri allowlist enforced OR no privilege boundary bypass.
            
            9. Changing Device Settings: Exported component receives attacker-controlled Intent data and invokes privileged device APIs without caller validation, using the victim app's own permissions.
               PRIVILEGED SINKS: NotificationManager (cancelAll, cancel, setInterruptionFilter), TelephonyManager (resetAllCarrierActions, setDataEnabled, setDataRoamingEnabled), WifiManager (setWifiEnabled, disconnect, removeNetwork), AudioManager (setRingerMode, setMicrophoneMute, setStreamVolume), Settings.Global/System/Secure.put*(), PowerManager (reboot, goToSleep), DevicePolicyManager (lockNow, wipeData, setCameraDisabled), ConnectivityManager.setAirplaneMode(), AlarmManager (setTime, setTimeZone), BluetoothAdapter (enable, disable), KeyguardManager.disableKeyguard()
               KEY DISTINCTION: Attacker controls WHETHER/HOW the operation executes - they trigger the component and the app invokes the privileged API with ITS OWN permissions.
               TRUE POSITIVE if: source exported (no permission restriction) AND tainted data drives a privileged API AND app holds required permission AND no checkCallingPermission/checkCallingUid/enforceCallingPermission guard.
               FALSE POSITIVE if: not exported OR requires signature permission OR guarded by caller identity check OR app lacks the required permission OR state is app-internal only OR values are hardcoded.
            
            8. PendingIntent Redirection: App creates a PendingIntent wrapping an implicit/empty Intent with FLAG_MUTABLE (or pre-SDK31 default mutable), exposes it to an attacker who calls .send(ctx, 0, fillInIntent) supplying the missing component - borrowing victim app's UID and permissions.
               SOURCE: PendingIntent.getActivity/getBroadcast/getService/getForegroundService() returns tainted PendingIntent.
               EXPOSURE SINKS: putExtra("key", pi) → sendBroadcast/startActivity/startService/setResult; NotificationCompat/Notification.Builder setContentIntent/setDeleteIntent/setFullScreenIntent; RemoteViews.setOnClickPendingIntent.
               VULNERABLE (all three required): (1) Wrapped Intent is implicit - no setComponent/setClass/setClassName/setPackage/new Intent(ctx,Class.class); (2) FLAG_MUTABLE used OR no flag with targetSdkVersion < 31; (3) PendingIntent reaches attacker via an exposure sink.
               FALSE POSITIVE if: explicit component set OR FLAG_IMMUTABLE used OR PendingIntent never leaves app process OR setPackage() restricts recipient.
               NOTE: If targetSdkVersion >= 31 and no FLAG_MUTABLE, system throws exception - code likely sets a flag, verify which one.
            
            YOUR JOB:
            1. Is this flow a TRUE POSITIVE or FALSE POSITIVE?
            2. If TRUE POSITIVE, generate a concrete POC.
            
            POC PATTERNS:
            1. WebView Vulnerability: Single adb command opening attacker URL (use https://example.com in case of arbitrary URL else decide yourself on cases of endswith etc.) with all required parameters.
            2. Third-Party Package Context Code Execution: Describe the attack steps.
            3. Intent Redirection: Single adb command targeting a non-exported component (identify from manifest). No generic examples.
            4. Implicit Intent Interception: Describe the attack and provide sample attacker AndroidManifest.xml intent-filter.
            5. Path Traversal: adb shell "content read --uri content://authority/../../files/profileInstalled" - always use this exact path, never URL-encode.
            6. Content Provider Proxy: Match to how URI enters the app:
               a) Via ContentProvider query param: adb shell "content query --uri content://com.victim.proxy/path?uri=content://com.victim.private/secrets"
               b) Via Activity deep link (getData().getQueryParameter()): adb shell "am start -a android.intent.action.VIEW -d 'https://host/path?target=content://com.victim.private/secrets' com.victim"
               c) Via Activity string extra: adb shell "am start -n com.victim/.Activity --es key 'content://com.victim.private/secrets'"
               d) Via Activity data URI: adb shell "am start -n com.victim/.Activity -d 'content://com.victim.private/secrets'"
               Identify a non-exported provider from the manifest as the target. No generic example URIs.
            7. Arbitrary File Write: Match to how Uri enters:
               a) Intent extra: adb shell "am start -n com.victim/.Activity --eu output 'file:///sdcard/Download/thorfinn_poc_target.jpg'"
               b) Intent data: adb shell "am start -n com.victim/.Activity -d 'file:///sdcard/Download/thorfinn_poc_target.jpg'"
               c) Action-based: adb shell "am start -a <action> -n com.victim/.Activity --eu output 'file:///sdcard/Download/thorfinn_poc_target.jpg'"
               Use actual component name and extra key from code.
            8. Changing Device Settings:
               a) BroadcastReceiver: adb shell "am broadcast -a <action> -n com.victim/.Receiver [extras]"
               b) Activity/Service: adb shell "am start -n com.victim/.Activity [extras]"
               Use -n for explicit component targeting (required on Android 8+). Pick the action triggering the highest-impact sink. Use actual extra key names from code.
            9. PendingIntent Redirection: Cannot exploit via adb - requires an attacker app.
               Start with: NO_ADB_COMMAND
               Provide: (a) how attacker receives PendingIntent (BroadcastReceiver/NotificationListenerService/onActivityResult); (b) full attacker Java code with pi.send(ctx, 0, fillInIntent) where fillInIntent.setClassName() targets a non-exported victim component (from manifest); (c) attacker AndroidManifest.xml snippet; (d) impact description.
            
            CRITICAL POC FORMATTING RULES:
            - ALL adb commands MUST be on a SINGLE LINE.
            - ALL adb commands MUST wrap the shell portion in double quotes: adb shell "am start ..."
            - NEVER use backslash line continuations (\\) in adb commands.
            
            RESPONSE FORMAT:
            
            === VERDICT ===
            TRUE_POSITIVE or FALSE_POSITIVE
            
            === VULNERABILITY CLASS ===
            (One of: Intent Redirection, WebView Vulnerability, Implicit Intent Interception, Insecure Content Provider, Insecure Broadcast, Path Traversal, SQL Injection, Code Execution, Insecure Deep Link, Insecure File Access, Arbitrary File Write, Changing Device Settings, Insecure Deserialization, Insecure Cryptography, Insecure Permissions, Third-Party Package Context Code Execution, Content Provider Path Traversal, Content Provider Proxy, PendingIntent Redirection, or any other specific class. If FALSE_POSITIVE, write "N/A")
            
            === ANALYSIS ===
            (Your detailed reasoning for this specific finding only)
            
            === POC ===
            (If TRUE_POSITIVE: adb command or exploit code. If FALSE_POSITIVE: N/A)
            
            POC RULES:
            - If adb CAN be used, provide ONLY the adb command. Don't URL encode URLs unless required based on code.
            - If adb CANNOT be used (Parcelable extras or requires attacker app):
              1. Start with exactly: NO_ADB_COMMAND
              2. Explain WHY adb cannot be used.
              3. Provide the FULL Java/Kotlin exploit code in a markdown code block.
            """;

    @Override
    public List<Finding> generateFindings() throws Exception {
        log.info("[*] Starting TaiE POC generation...");

        ToolsConfig toolsConfig = ConfigContext.getConfig().getToolsConfig();
        String decompiler = toolsConfig.getDecompilers();
        boolean isJadx = "jadx".equalsIgnoreCase(decompiler);

        log.info("[*] Decompiler used: {} - sending {} files to LLM", decompiler, isJadx ? ".java" : ".smali");

        LLMClient llmClient = new LLMClient(
                toolsConfig.getLlmApiKey(),
                toolsConfig.getLlmModel(),
                toolsConfig.getLlmBaseUrl()
        );

        boolean useAgentMode = toolsConfig.isTaiEAgentEnabled();
        TaiEAgentRunner agentRunner = null;
        if (useAgentMode) {
            try {
                String decompiledRoot = Paths.get(PathUtils.getDecompiledApkPath()).toAbsolutePath().toString();
                agentRunner = new TaiEAgentRunner(toolsConfig, decompiledRoot);
                log.info("[*] TaiE execution mode: AGENT (chat fallback enabled)");
            } catch (Exception e) {
                useAgentMode = false;
                log.warn("[!] TaiE agent init failed, falling back to chat mode: {}", e.getMessage());
            }
        }
        if (!useAgentMode) {
            log.info("[*] TaiE execution mode: CHAT");
        }

        TaiEParser parser = new TaiEParser();
        TaiEResult taieResult = parser.parse();

        String manifest = findAndReadManifest();
        String manifestPath = findManifestPath();
        String decompiledRoot = Paths.get(PathUtils.getDecompiledApkPath()).toAbsolutePath().toString();
        this.codeLookupService = new TaiECodeLookupService(decompiledRoot);

        String systemPrompt = (isJadx ? SYSTEM_PROMPT_INTRO_JAVA : SYSTEM_PROMPT_INTRO_SMALI) + SYSTEM_PROMPT_BODY;

        log.info("[*] Processing {} taint flow(s) through LLM...", taieResult.getTaintFlows().size());

        StringBuilder allResults = new StringBuilder();
        allResults.append("# TaiE LLM Analysis Results\n\n");
        allResults.append("**Date:** ").append(java.time.LocalDateTime.now()).append("\n\n");
        allResults.append("| # | Source | Sink | Verdict |\n");
        allResults.append("|---|--------|------|--------|\n");

        StringBuilder detailedResults = new StringBuilder();
        detailedResults.append("\n---\n\n## Detailed Analysis\n\n");

        int truePositives = 0;
        int falsePositives = 0;
        List<Finding> findings = new ArrayList<>();

        for (int i = 0; i < taieResult.getTaintFlows().size(); i++) {
            TaintFlowInfo flow = taieResult.getTaintFlows().get(i);
            log.info("[*] Analyzing flow {}/{}: {} -> {}", i + 1, taieResult.getTaintFlows().size(),
                    flow.getSourceFile(), flow.getSinkFile());

            String sourceCode = isJadx
                    ? findAndReadJava(flow.getSourceFile())
                    : findAndReadSmali(flow.getSourceFile());
            String sinkCode = flow.getSourceFile().equals(flow.getSinkFile())
                    ? sourceCode
                    : isJadx ? findAndReadJava(flow.getSinkFile()) : findAndReadSmali(flow.getSinkFile());

            Map<String, String> intermediateCode = new LinkedHashMap<>();
            if (flow.getIntermediateClasses() != null) {
                for (String intermediateClass : flow.getIntermediateClasses()) {
                    if (intermediateClass.equals(flow.getSourceFile()) || intermediateClass.equals(flow.getSinkFile())) {
                        continue;
                    }
                    String code = isJadx
                            ? findAndReadJava(intermediateClass)
                            : findAndReadSmali(intermediateClass);
                    boolean notFound = code.startsWith("Java file not found for:") || code.startsWith("Smali file not found for:");
                    if (!notFound) {
                        intermediateCode.put(intermediateClass, code);
                        log.info("[*]     Loaded intermediate class: {}", intermediateClass);
                    } else {
                        log.warn("[*]     Intermediate class file not found: {}", intermediateClass);
                    }
                }
            }

            boolean sourceNotFound = sourceCode.startsWith("Java file not found for:") || sourceCode.startsWith("Smali file not found for:");
            boolean sinkNotFound = sinkCode.startsWith("Java file not found for:") || sinkCode.startsWith("Smali file not found for:");

            if (sourceNotFound || sinkNotFound) {
                String reason = sourceNotFound && sinkNotFound
                        ? "Both source and sink class files not found"
                        : sourceNotFound ? "Source class file not found" : "Sink class file not found";
                log.warn("[*]   Flow {}: Skipping - {}", i + 1, reason);
                continue;
            }

            String codeLabel = isJadx ? "JAVA" : "SMALI";
            String userPrompt = buildUserPrompt(flow, sourceCode, sinkCode, intermediateCode, manifest, codeLabel);

            try {
                String llmResponse;
                if (useAgentMode) {
                    try {
                        TaiEAgentModels.FlowRequest request = new TaiEAgentModels.FlowRequest(
                                flow.getSourceFile(),
                                flow.getSinkFile(),
                                flow.getRawFlow(),
                                flow.getFlowDescription(),
                                flow.getFlowPath()
                        );
                        TaiEAgentModels.FlowResponse response = agentRunner.analyze(request);
                        llmResponse = toLegacyResponse(response);
                    } catch (Exception agentError) {
                        log.warn("[!] Agent analysis failed for flow {}. Falling back to chat: {}", i + 1, agentError.getMessage());
                        llmResponse = llmClient.chat(systemPrompt, userPrompt);
                    }
                } else {
                    llmResponse = llmClient.chat(systemPrompt, userPrompt);
                }

                boolean isTruePositive = llmResponse.contains("TRUE_POSITIVE");
                if (isTruePositive) {
                    truePositives++;
                    String vulnClass = extractSection(llmResponse, "=== VULNERABILITY CLASS ===", "=== ANALYSIS ===");
                    String rawPoc = extractSection(llmResponse, "=== POC ===", null);
                    String cleanPoc = extractPocCommand(rawPoc);
                    findings.add(Finding.builder()
                            .tool("taie")
                            .truePositive(true)
                            .sourceFile(flow.getSourceFile())
                            .sinkFile(flow.getSinkFile())
                            .rawFlow(flow.getRawFlow())
                            .vulnerabilityClass(vulnClass)
                            .analysis(extractSection(llmResponse, "=== ANALYSIS ===", "=== POC ==="))
                            .poc(cleanPoc)
                            .build());
                } else {
                    falsePositives++;
                    findings.add(Finding.builder()
                            .tool("taie")
                            .truePositive(false)
                            .sourceFile(flow.getSourceFile())
                            .sinkFile(flow.getSinkFile())
                            .rawFlow(flow.getRawFlow())
                            .analysis(extractSection(llmResponse, "=== ANALYSIS ===", "=== POC ==="))
                            .build());
                }

                String verdictLabel = isTruePositive ? "✅ TRUE POSITIVE" : "❌ FALSE POSITIVE";

                allResults.append(String.format("| %d | `%s` | `%s` | %s |\n",
                        i + 1, flow.getSourceFile(),
                        flow.getSinkFile(), verdictLabel));

                detailedResults.append(String.format("### Flow %d\n\n", i + 1));
                detailedResults.append(String.format("- **Source:** `%s`\n", flow.getSourceFile()));
                detailedResults.append(String.format("- **Sink:** `%s`\n", flow.getSinkFile()));
                detailedResults.append(String.format("- **Verdict:** %s\n", verdictLabel));
                detailedResults.append(String.format("- **Raw Flow:**\n```\n%s\n```\n\n", flow.getRawFlow()));
                detailedResults.append("#### LLM Response\n\n");
                detailedResults.append(llmResponse).append("\n\n---\n\n");

                log.info("[*]   Flow {}: {}", i + 1, isTruePositive ? "TRUE POSITIVE" : "FALSE POSITIVE");

            } catch (Exception e) {
                log.error("[!] LLM analysis failed for flow {}: {}", i + 1, e.getMessage());
                findings.add(Finding.builder()
                        .tool("taie")
                        .truePositive(false)
                        .sourceFile(flow.getSourceFile())
                        .sinkFile(flow.getSinkFile())
                        .rawFlow(flow.getRawFlow())
                        .analysis("LLM analysis failed: " + e.getMessage() + ". Manual review required.")
                        .build());
                allResults.append(String.format("| %d | `%s` | `%s` | ⚠️ ERROR |\n",
                        i + 1, flow.getSourceFile(),
                        flow.getSinkFile()));

                detailedResults.append(String.format("### Flow %d\n\n", i + 1));
                detailedResults.append(String.format("- **Source:** `%s`\n", flow.getSourceFile()));
                detailedResults.append(String.format("- **Sink:** `%s`\n", flow.getSinkFile()));
                detailedResults.append(String.format("- **Verdict:** ⚠️ ERROR\n"));
                detailedResults.append(String.format("- **Error:** `%s`\n\n---\n\n", e.getMessage()));
            }
        }

        allResults.append(String.format("\n## Summary\n\n| Metric | Count |\n|--------|-------|\n| True Positives | %d |\n| False Positives | %d |\n| Errors | %d |\n| **Total** | **%d** |\n",
                truePositives, falsePositives,
                taieResult.getTaintFlows().size() - truePositives - falsePositives,
                taieResult.getTaintFlows().size()));

        allResults.append(detailedResults);

        String outputPath = Paths.get(PathUtils.getOutputPath(), "taie_poc_results.md").toString();
        try (FileWriter writer = new FileWriter(outputPath)) {
            writer.write(allResults.toString());
        }

        log.info("[*] POC results saved to: {}", outputPath);
        log.info("[*] Summary - True Positives: {}, False Positives: {}, Total: {}",
                truePositives, falsePositives, taieResult.getTaintFlows().size());

        log.info("[*] Confirmed findings: {}", findings.size());
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            log.info("[*]   Finding {}: {} -> {} [{}]", i + 1,
                    f.getSourceFile(),
                    f.getSinkFile(),
                    f.getVulnerabilityClass());
        }

        return findings;
    }

    private String buildUserPrompt(TaintFlowInfo flow, String sourceCode, String sinkCode,
                                    Map<String, String> intermediateCode,
                                    String manifest, String codeLabel) {
        StringBuilder prompt = new StringBuilder();

        prompt.append("=== TAINT FLOW FINDING ===\n");
        prompt.append("Source Class: ").append(flow.getSourceFile()).append("\n");
        prompt.append("Sink Class: ").append(flow.getSinkFile()).append("\n");
        prompt.append("Raw Flow: ").append(flow.getRawFlow()).append("\n");

        if (flow.getFlowDescription() != null && !flow.getFlowDescription().isEmpty()) {
            prompt.append("Full Taint Flow Path: ").append(flow.getFlowDescription()).append("\n");
        }
        if (flow.getFlowPath() != null && !flow.getFlowPath().isEmpty()) {
            prompt.append("All Classes Involved in Flow: ").append(String.join(" → ", flow.getFlowPath())).append("\n");
        }
        if (flow.getIntermediateClasses() != null && !flow.getIntermediateClasses().isEmpty()) {
            prompt.append("Intermediate Classes (between source and sink): ").append(String.join(", ", flow.getIntermediateClasses())).append("\n");
        }
        prompt.append("\n");

        prompt.append("=== SOURCE CLASS ").append(codeLabel).append(" CODE (").append(flow.getSourceFile()).append(") ===\n");
        prompt.append(sourceCode).append("\n\n");

        if (!flow.getSourceFile().equals(flow.getSinkFile())) {
            prompt.append("=== SINK CLASS ").append(codeLabel).append(" CODE (").append(flow.getSinkFile()).append(") ===\n");
            prompt.append(sinkCode).append("\n\n");
        }

        if (!intermediateCode.isEmpty()) {
            for (Map.Entry<String, String> entry : intermediateCode.entrySet()) {
                prompt.append("=== INTERMEDIATE CLASS ").append(codeLabel).append(" CODE (").append(entry.getKey()).append(") ===\n");
                prompt.append(entry.getValue()).append("\n\n");
            }
        }

        prompt.append("=== ANDROID MANIFEST ===\n");
        prompt.append(manifest).append("\n");

        return prompt.toString();
    }

    private String findAndReadJava(String className) {
        try {
            String content = getCodeLookupService().readJavaClassWithFuzzy(className);
            if (content.startsWith("Java file not found for:")) {
                log.warn("[!] Java file not found for class: {}", className);
            } else {
                log.info("[*]   Loaded java via fuzzy lookup: {}", className);
            }
            return content;
        } catch (Exception e) {
            log.error("[!] Failed to read java file for {}: {}", className, e.getMessage());
            return "Java file not found for: " + className;
        }
    }

    private void findFilesByName(File dir, String fileName, List<File> results) {
        File[] children = dir.listFiles();
        if (children == null) return;
        for (File child : children) {
            if (child.isDirectory()) {
                findFilesByName(child, fileName, results);
            } else if (child.getName().equals(fileName)) {
                results.add(child);
            }
        }
    }

    private String findAndReadSmali(String className) {
        try {
            String content = getCodeLookupService().readSmaliClassWithFuzzy(className);
            if (content.startsWith("Smali file not found for:")) {
                log.warn("[!] Smali file not found for class: {}", className);
            } else {
                log.info("[*]   Loaded smali via fuzzy lookup: {}", className);
            }
            return content;
        } catch (Exception e) {
            log.error("[!] Failed to read smali file for {}: {}", className, e.getMessage());
            return "Smali file not found for: " + className;
        }
    }

    private TaiECodeLookupService getCodeLookupService() {
        if (codeLookupService == null) {
            String decompiledRoot = Paths.get(PathUtils.getDecompiledApkPath()).toAbsolutePath().toString();
            codeLookupService = new TaiECodeLookupService(decompiledRoot);
        }
        return codeLookupService;
    }

    private String findAndReadManifest() {
        String decompiledPath = PathUtils.getDecompiledApkPath();
        String[] possiblePaths = {
                decompiledPath + "AndroidManifest.xml",
                decompiledPath + "resources/AndroidManifest.xml"
        };
        for (String path : possiblePaths) {
            File file = new File(path);
            if (file.exists()) {
                log.info("[*] Found AndroidManifest.xml at: {}", path);
                return readFileContent(path);
            }
        }
        log.warn("[!] AndroidManifest.xml not found in decompiled output");
        return "AndroidManifest.xml not found";
    }

    private String findManifestPath() {
        String decompiledPath = PathUtils.getDecompiledApkPath();
        String[] possiblePaths = {
                decompiledPath + "AndroidManifest.xml",
                decompiledPath + "resources/AndroidManifest.xml"
        };
        for (String path : possiblePaths) {
            File file = new File(path);
            if (file.exists()) {
                return Paths.get(path).toAbsolutePath().toString();
            }
        }
        return "";
    }

    private String readFileContent(String filePath) {
        try {
            return Files.readString(Path.of(filePath));
        } catch (Exception e) {
            log.error("[!] Failed to read file: {}", filePath);
            return "File not found: " + filePath;
        }
    }

    private String extractSection(String response, String startMarker, String endMarker) {
        int startIdx = response.indexOf(startMarker);
        if (startIdx == -1) {
            return "";
        }
        startIdx += startMarker.length();
        int endIdx = (endMarker != null) ? response.indexOf(endMarker, startIdx) : -1;
        String section = (endIdx != -1) ? response.substring(startIdx, endIdx) : response.substring(startIdx);
        return section.trim();
    }

    private String extractPocCommand(String rawPoc) {
        if (rawPoc == null || rawPoc.isBlank() || rawPoc.equalsIgnoreCase("N/A")) {
            return rawPoc;
        }

        String cleaned = rawPoc.trim();

        if (cleaned.startsWith("NO_ADB_COMMAND")) {
            cleaned = cleaned.replaceAll("```\\w*\\s*\\n", "").replaceAll("```", "");
            return cleaned.trim();
        }

        if (cleaned.contains("```")) {
            int startFence = cleaned.indexOf("```");
            int afterFirstFence = cleaned.indexOf('\n', startFence);
            if (afterFirstFence == -1) {
                afterFirstFence = startFence + 3;
            } else {
                afterFirstFence += 1;
            }
            int endFence = cleaned.indexOf("```", afterFirstFence);
            if (endFence != -1) {
                cleaned = cleaned.substring(afterFirstFence, endFence).trim();
            } else {
                cleaned = cleaned.substring(afterFirstFence).trim();
            }
        }

        String[] lines = cleaned.split("\n");
        StringBuilder command = new StringBuilder();
        boolean inCommand = false;
        boolean prevLineHasBackslash = false;

        for (String line : lines) {
            String trimmed = line.trim();

            if (!inCommand) {
                if (trimmed.startsWith("adb")) {
                    inCommand = true;
                    command.append(line);
                    prevLineHasBackslash = trimmed.endsWith("\\");
                    if (prevLineHasBackslash) {
                        command.append("\n");
                    }
                }
            } else {
                if (prevLineHasBackslash) {
                    command.append(line);
                    prevLineHasBackslash = trimmed.endsWith("\\");
                    if (prevLineHasBackslash) {
                        command.append("\n");
                    }
                } else {
                    break;
                }
            }
        }

        String result = command.toString().trim();
        if (!result.isEmpty()) {
            return normalizeAdbCommand(result);
        }

        StringBuilder fallback = new StringBuilder();
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() && fallback.length() > 0) {
                break;
            }
            if (!trimmed.isEmpty()) {
                if (fallback.length() > 0) fallback.append("\n");
                fallback.append(line);
            }
        }
        return normalizeAdbCommand(fallback.toString().trim());
    }

    private String normalizeAdbCommand(String cmd) {
        if (cmd == null || cmd.isBlank()) {
            return cmd;
        }

        String singleLine = cmd.replaceAll("\\\\\\s*\\n\\s*", " ")
                               .replaceAll("\\s+", " ")
                               .trim();

        if (singleLine.startsWith("adb shell ")) {
            String shellPart = singleLine.substring("adb shell ".length()).trim();

            if (shellPart.startsWith("\"") && shellPart.endsWith("\"")) {
                return singleLine;
            }

            if (shellPart.startsWith("\"")) {
                shellPart = shellPart.substring(1);
            }
            if (shellPart.endsWith("\"")) {
                shellPart = shellPart.substring(0, shellPart.length() - 1);
            }

            shellPart = shellPart.replace("\"", "\\\"");

            return "adb shell \"" + shellPart + "\"";
        }

        return singleLine;
    }

    private String toLegacyResponse(TaiEAgentModels.FlowResponse response) {
        String verdict = response.verdict() == null || response.verdict().isBlank()
                ? "FALSE_POSITIVE"
                : response.verdict().trim();
        String vulnerabilityClass = response.vulnerabilityClass() == null || response.vulnerabilityClass().isBlank()
                ? "N/A"
                : response.vulnerabilityClass().trim();
        String analysis = response.analysis() == null ? "" : response.analysis().trim();
        String poc = response.poc() == null || response.poc().isBlank() ? "N/A" : response.poc().trim();

        return "=== VERDICT ===\n"
                + verdict + "\n\n"
                + "=== VULNERABILITY CLASS ===\n"
                + vulnerabilityClass + "\n\n"
                + "=== ANALYSIS ===\n"
                + analysis + "\n\n"
                + "=== POC ===\n"
                + poc;
    }

}
