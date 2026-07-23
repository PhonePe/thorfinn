package com.thorfinn.poc;

import com.thorfinn.config.ConfigContext;
import com.thorfinn.config.ToolsConfig;
import com.thorfinn.models.Finding;
import com.thorfinn.models.SemgrepResult;
import com.thorfinn.models.SemgrepResult.SemgrepFinding;
import com.thorfinn.parsers.SemgrepParser;
import com.thorfinn.utils.LLMClient;
import com.thorfinn.utils.PathUtils;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class SemgrepPOC implements poc {

    private static final String DYNAMIC_RECEIVER_SYSTEM_PROMPT = """
            You are an expert Android security researcher. You will be given:
            1. A semgrep finding showing a dynamically registered BroadcastReceiver with a custom IntentFilter action.
            2. The source code of the Activity/class where registerReceiver() is called.
            3. The source code of the BroadcastReceiver class (its onReceive method).
            4. The AndroidManifest.xml.
            
            YOUR JOB:
            Determine if the action used in the IntentFilter is a CUSTOM action or a standard Android system action.
            If it is a custom action, generate a POC to invoke it.
            
            IMPORTANT - VARIABLE RESOLUTION:
            - The action may be provided as a string literal (e.g., "com.example.MY_ACTION") or as a variable/field name (e.g., GET_FLAG, MY_ACTION_CONSTANT).
            - If the action is a variable, you MUST look at the source code to find where that variable is defined and resolve it to its actual string value.
            - For example, if the code has `public static String GET_FLAG = "io.hextree.broadcast.GET_FLAG"` and the IntentFilter uses `new IntentFilter(GET_FLAG)`, the actual action is "io.hextree.broadcast.GET_FLAG".
            - Always use the resolved string value in your verdict and POC - never use the variable name.
            
            KEY RULES:
            - If the action is a custom action (i.e., NOT a standard system broadcast), it is a TRUE POSITIVE.
            - System action prefixes to treat as FALSE POSITIVE: android.intent.action.*, android.net.*, android.media.*, android.bluetooth.*, android.hardware.*, android.app.action.*, android.os.action.*, android.provider.*, android.telephony.*, android.nfc.*, android.appwidget.*, android.accounts.*, android.location.*, android.security.*, com.google.*, com.android.*, androidx.*
            - If the action is a standard Android system action (e.g., android.intent.action.BOOT_COMPLETED, android.intent.action.BATTERY_LOW, etc.), it is a FALSE POSITIVE.
            - A custom action means any external app can craft and send a broadcast with that action, making the receiver reachable.
            - Even if the onReceive method does NOT contain a dangerous source-sink flow, a custom action receiver is STILL a true positive - the receiver is externally invocable and that alone is a security concern.
            - You should still review onReceive to note what it does, but do NOT mark it as false positive just because there is no obvious dangerous sink.
            - If RECEIVER_NOT_EXPORTED (value 4) flag is explicitly used, it is a FALSE POSITIVE.
            - If a permission is required to send to this receiver (3-arg registerReceiver with permission string), it is a FALSE POSITIVE.
            
            POC GENERATION (only if TRUE_POSITIVE):
            - Generate a single adb command to send a broadcast with the custom action.
            - Format: adb shell am broadcast -a <custom_action>
            - Extract the exact action string from the code and use it in the command.
            - Do NOT add extras, flags, or anything else - just the action.
            - Example: adb shell am broadcast -a com.example.MY_CUSTOM_ACTION
            
            RESPONSE FORMAT:
            
            === VERDICT ===
            TRUE_POSITIVE or FALSE_POSITIVE
            
            === VULNERABILITY CLASS ===
            Dynamic Broadcast Receiver (always use this exact class name if TRUE_POSITIVE, write "N/A" if FALSE_POSITIVE)
            
            === POC ===
            (The single adb broadcast command if TRUE_POSITIVE, write "N/A" if FALSE_POSITIVE)
            
            === ANALYSIS ===
            (Your detailed reasoning - note whether the action is custom or system, and briefly describe what onReceive does)
            """;

    private static final String SQL_INJECTION_SYSTEM_PROMPT = """
            You are an expert Android security researcher. You will be given:
            1. A semgrep finding showing a potential SQL injection in an Android app.
            2. The source code of the class where the SQL injection was detected.
            3. The AndroidManifest.xml.
            
            YOUR JOB:
            Determine if this SQL injection is exploitable by an external attacker (TRUE POSITIVE) or not (FALSE POSITIVE).
            
            UNDERSTANDING CLIENT-SIDE SQL INJECTION IN ANDROID:
            - Android apps use SQLite databases locally. SQL injection occurs when attacker-controlled input
              is concatenated into raw SQL queries without parameterization.
            - There are MULTIPLE attack surfaces - not just ContentProviders:
            
            ATTACK SURFACE 1 - EXPORTED ContentProviders:
            - When a ContentProvider is exported, external apps can call query()/insert()/update()/delete(),
              providing attacker-controlled: projection, selection, sortOrder, URI path segments.
            - selectionArgs are parameterized (safe), but selection/projection/sortOrder are often concatenated raw.
            
            ATTACK SURFACE 2 - EXPORTED Activities/Services receiving Intent extras:
            - An exported Activity or Service receives attacker-controlled data via Intent extras
              (getStringExtra, getIntExtra, getData, etc.) which flows into raw SQL queries.
            - Example: An exported SearchActivity receives a search query via Intent extra "query",
              and concatenates it into rawQuery("SELECT * FROM items WHERE name='" + query + "'").
            - The attacker launches the activity with: adb shell "am start -n com.example/.SearchActivity --es query \"' OR 1=1--\""
            
            ATTACK SURFACE 3 - Deep links:
            - An Activity with a deep link intent-filter receives attacker-controlled URI data
              (getIntent().getData().getQueryParameter()) which flows into SQL.
            - The attacker triggers: adb shell "am start -a android.intent.action.VIEW -d 'myapp://search?q=\\' OR 1=1--'"
            
            ATTACK SURFACE 4 - BroadcastReceivers:
            - A dynamically or statically registered BroadcastReceiver receives Intent extras that flow into SQL.
            
            NOT AN ATTACK SURFACE:
            - Pure UI form input (user typing into EditText) going into their own local SQLite is NOT a security
              issue - the user is modifying their own database. Only flag this if the input path starts from
              an EXTERNAL source (Intent extras, deep links, ContentProvider parameters, broadcast data).
            
            IMPACT OF SQL INJECTION IN ANDROID:
            - Read data from OTHER tables in the same database (e.g., user credentials, tokens, private data)
            - Use UNION SELECT to extract data from any table
            - Use subqueries to enumerate table names: SELECT * FROM sqlite_master
            - In some cases, ATTACH DATABASE to read/write arbitrary files
            - Bypass authentication or access control logic
            
            VULNERABLE CONDITIONS (ALL must be true for TRUE POSITIVE):
            1. The vulnerable code is reachable from an EXPORTED component:
               a) An exported ContentProvider (android:exported="true" or default exported on SDK < 17)
               b) An exported Activity/Service that receives Intent extras flowing into SQL
               c) An Activity with deep link intent-filter whose URI data flows into SQL
               d) A BroadcastReceiver (exported or dynamic with custom action) whose data flows into SQL
            2. Attacker-controlled input (selection, projection, sortOrder, URI path segments, Intent extras,
               deep link query params, broadcast extras) is CONCATENATED into a SQL string - not passed via
               selectionArgs/bindArgs parameterization
            3. The concatenated string is passed to rawQuery(), execSQL(), compileStatement(), or
               SQLiteQueryBuilder without proper sanitization
            
            FALSE POSITIVE CONDITIONS:
            - The component containing or reachable from the SQL code is NOT exported
            - The component requires a signature-level permission that blocks third-party access
            - The input is passed via selectionArgs (parameterized) - e.g., rawQuery("SELECT * FROM t WHERE id=?", new String[]{input})
            - The input is validated/sanitized before concatenation (e.g., Integer.parseInt(), allowlisted column names)
            - The SQL is constructed entirely from hardcoded strings (no external input)
            - The input comes ONLY from UI form fields (EditText) with no external injection path
            - The class is NOT reachable from any exported component
            
            POC GENERATION (only if TRUE_POSITIVE):
            - Generate an adb command that exploits the SQL injection.
            - You MUST examine the manifest to identify the exported component and its entry point.
            
            FOR CONTENTPROVIDER-BASED INJECTION:
            - Find the provider's android:authorities value in the manifest.
            - Common POC patterns:
            
            a) Injection via selection (WHERE clause):
               adb shell "content query --uri content://com.example.provider/table --where \"1=1) UNION SELECT sql,2,3 FROM sqlite_master--\""
            
            b) Injection via projection (column names):
               adb shell "content query --uri content://com.example.provider/table --projection \"* FROM sqlite_master--\""
            
            c) Injection via sortOrder:
               adb shell "content query --uri content://com.example.provider/table --sort \"1; SELECT * FROM sqlite_master\""
            
            FOR ACTIVITY/SERVICE-BASED INJECTION (Intent extras):
            - Find the exported Activity/Service component name in the manifest.
            - Identify the Intent extra key name from the source code.
            - POC pattern:
               adb shell "am start -n com.example/.VulnerableActivity --es search_query \"' UNION SELECT sql FROM sqlite_master--\""
            
            FOR DEEP LINK-BASED INJECTION:
            - Find the deep link scheme/host from the intent-filter in the manifest.
            - Identify the query parameter name from the source code.
            - POC pattern:
               adb shell "am start -a android.intent.action.VIEW -d 'myapp://search?q=\\' UNION SELECT sql FROM sqlite_master--'"
            
            - Identify WHICH parameter is injectable from the code and craft the POC accordingly.
            - Target sqlite_master to prove arbitrary table access.
            - The adb command MUST be on a SINGLE LINE wrapped in double quotes.
            
            RESPONSE FORMAT:
            
            === VERDICT ===
            TRUE_POSITIVE or FALSE_POSITIVE
            
            === VULNERABILITY CLASS ===
            SQL Injection (always use this exact class name if TRUE_POSITIVE, write "N/A" if FALSE_POSITIVE)
            
            === POC ===
            (The single adb command if TRUE_POSITIVE, write "N/A" if FALSE_POSITIVE)
            
            === ANALYSIS ===
            (Your detailed reasoning - explain the attack surface (ContentProvider/Activity/DeepLink/Broadcast),
            which parameter is injectable, which SQL method is used, whether the component is exported,
            and what data an attacker could extract)
            """;

    @Override
    public List<Finding> generateFindings() throws Exception {
        log.info("[*] Processing Semgrep findings with LLM verification...");

        ToolsConfig toolsConfig = ConfigContext.getConfig().getToolsConfig();
        LLMClient llmClient = new LLMClient(
            toolsConfig
        );

        SemgrepParser parser = new SemgrepParser();
        SemgrepResult semgrepResult = parser.parse();

        List<SemgrepFinding> sortedFindings = new ArrayList<>(semgrepResult.getFindings());
        sortedFindings.sort((a, b) -> rulePriority(a.getRuleId()) - rulePriority(b.getRuleId()));

        String manifest = findAndReadManifest();
        List<Finding> findings = new ArrayList<>();

        log.info("[*] Processing {} semgrep finding(s) through LLM...", sortedFindings.size());

        Set<String> processedFileLines = new HashSet<>();

        for (int i = 0; i < sortedFindings.size(); i++) {
            SemgrepFinding sf = sortedFindings.get(i);
            String ruleId = sf.getRuleId();
            String vulnClass = mapRuleToVulnClass(ruleId);

            log.info("────────────────────────────────────────────────────");
            log.info("[*] Semgrep Finding {}/{}", i + 1, sortedFindings.size());
            log.info("[*]   Rule ID    : {}", ruleId);
            log.info("[*]   Severity   : {}", sf.getSeverity());
            log.info("[*]   File       : {}", toRelativePath(sf.getFilePath()));
            log.info("[*]   Line       : {}", sf.getLineNumber());
            log.info("[*]   Vuln Class : {}", vulnClass);
            log.info("[*]   Message    : {}", sf.getMessage());
            if (sf.getMetavars() != null && !sf.getMetavars().isEmpty()) {
                log.info("[*]   Metavariables:");
                sf.getMetavars().forEach((key, value) ->
                        log.info("[*]     {} = {}", key, value));
            }

            String dedupeKey = sf.getFilePath();
            if (processedFileLines.contains(dedupeKey)) {
                log.info("[*]   Skipping - already processed this file from a more specific rule");
                log.info("────────────────────────────────────────────────────");
                continue;
            }

            if (ruleId != null && (ruleId.contains("exported-flag") || ruleId.contains("exported-constant"))) {
                log.info("[*]   Skipping exported-flag rule - relying on action-specific rules for analysis");
                log.info("────────────────────────────────────────────────────");
                continue;
            }

            log.info("────────────────────────────────────────────────────");

            if (ruleId != null && ruleId.contains("dynamic-receiver")) {
                Finding finding = processDynamicReceiverFinding(sf, llmClient, manifest, vulnClass);
                if (finding != null) {
                    findings.add(finding);
                    processedFileLines.add(dedupeKey);
                }
            } else if (ruleId != null && ruleId.contains("sql-injection")) {
                Finding finding = processSqlInjectionFinding(sf, llmClient, manifest, vulnClass);
                if (finding != null) {
                    findings.add(finding);
                    processedFileLines.add(dedupeKey);
                }
            } else {
                findings.add(Finding.builder()
                        .tool("semgrep")
                        .truePositive(true)
                        .sourceFile(sf.getFilePath())
                        .sinkFile(sf.getFilePath())
                        .rawFlow(null)
                        .vulnerabilityClass(vulnClass)
                        .analysis(sf.getMessage())
                        .poc(null)
                        .build());
            }
        }

        log.info("[*] Semgrep findings after LLM verification: {}", findings.size());
        return findings;
    }

    private Finding processDynamicReceiverFinding(SemgrepFinding sf, LLMClient llmClient,
                                                   String manifest, String vulnClass) {
        Map<String, String> metavars = sf.getMetavars();
        boolean hasMetavars = metavars != null && !metavars.isEmpty()
                && metavars.values().stream().anyMatch(v -> v != null && !v.isBlank());

        String registeringCode = readFileByPath(sf.getFilePath());
        if (registeringCode.startsWith("File not found")) {
            log.warn("[!] Could not read registering class file: {}", sf.getFilePath());
            return null;
        }

        String receiverClassName = null;
        String action = "unknown";

        if (hasMetavars) {
            receiverClassName = metavars.get("$RECEIVER_CLASS");
            action = metavars.getOrDefault("$ACTION", "unknown");
        }

        if ((receiverClassName == null || receiverClassName.isBlank()) && sf.getMessage() != null) {
            Matcher rcMatcher = Pattern.compile("BroadcastReceiver\\s+'([^']+)'").matcher(sf.getMessage());
            if (rcMatcher.find()) {
                receiverClassName = rcMatcher.group(1);
            }
        }
        if (("unknown".equals(action) || action == null) && sf.getMessage() != null) {
            Matcher actMatcher = Pattern.compile("action\\s+(\\S+)").matcher(sf.getMessage());
            if (actMatcher.find()) {
                action = actMatcher.group(1).replaceAll("[.,;]+$", "");
            }
        }

        String receiverCode = "";
        if (receiverClassName != null && !receiverClassName.isBlank()) {
            receiverClassName = receiverClassName.replaceAll("new\\s+", "").replaceAll("\\(.*", "").trim();
            receiverCode = findAndReadJava(receiverClassName);
            if (receiverCode.startsWith("Java file not found")) {
                log.warn("[!] Receiver class not found: {} - will send registering file only", receiverClassName);
                receiverCode = "";
            }
        }

        log.info("[*]   Receiver class: {}", receiverClassName != null ? receiverClassName : "unknown");
        log.info("[*]   Action: {}", action);

        StringBuilder userPrompt = new StringBuilder();
        userPrompt.append("=== SEMGREP FINDING ===\n");
        userPrompt.append("Rule: ").append(sf.getRuleId()).append("\n");
        userPrompt.append("Action: ").append(action).append("\n");
        userPrompt.append("File: ").append(sf.getFilePath()).append("\n");
        userPrompt.append("Line: ").append(sf.getLineNumber()).append("\n\n");

        userPrompt.append("=== REGISTERING CLASS CODE ===\n");
        userPrompt.append(registeringCode).append("\n\n");

        if (!receiverCode.isEmpty()) {
            userPrompt.append("=== BROADCASTRECEIVER CLASS CODE (").append(receiverClassName).append(") ===\n");
            userPrompt.append(receiverCode).append("\n\n");
        }

        userPrompt.append("=== ANDROID MANIFEST ===\n");
        userPrompt.append(manifest).append("\n");

        try {
            String llmResponse = llmClient.chat(DYNAMIC_RECEIVER_SYSTEM_PROMPT, userPrompt.toString());

            boolean isTruePositive = llmResponse.contains("TRUE_POSITIVE");
            String analysis = extractSection(llmResponse, "=== ANALYSIS ===", null);
            String llmVulnClass = extractSection(llmResponse, "=== VULNERABILITY CLASS ===", "=== POC ===");
            String llmPoc = extractSection(llmResponse, "=== POC ===", "=== ANALYSIS ===");

            log.info("[*]   Finding {}: {} - {}",
                    toRelativePath(sf.getFilePath()), isTruePositive ? "TRUE POSITIVE" : "FALSE POSITIVE",
                    llmVulnClass.isEmpty() ? vulnClass : llmVulnClass);

            String cleanPoc = null;
            if (isTruePositive) {
                if (!llmPoc.isEmpty() && !llmPoc.equalsIgnoreCase("N/A") && llmPoc.startsWith("adb")) {
                    cleanPoc = llmPoc.trim();
                } else {
                    String cleanAction = action != null ? action.replace("\"", "").trim() : "unknown";
                    cleanPoc = "adb shell am broadcast -a " + cleanAction;
                }
                log.info("[*]   POC: {}", cleanPoc);
            }

            return Finding.builder()
                    .tool("semgrep")
                    .truePositive(isTruePositive)
                    .sourceFile(sf.getFilePath())
                    .sinkFile(receiverClassName != null ? receiverClassName : sf.getFilePath())
                    .rawFlow(null)
                    .vulnerabilityClass(llmVulnClass.isEmpty() ? vulnClass : llmVulnClass)
                    .analysis(analysis)
                    .poc(cleanPoc)
                    .build();

        } catch (Exception e) {
            log.error("[!] LLM analysis failed for semgrep finding: {}", e.getMessage());
            return Finding.builder()
                    .tool("semgrep")
                    .truePositive(false)
                    .sourceFile(sf.getFilePath())
                    .sinkFile(sf.getFilePath())
                    .rawFlow(null)
                    .vulnerabilityClass(vulnClass)
                    .analysis("LLM analysis failed: " + e.getMessage() + ". Manual review required.")
                    .poc(null)
                    .build();
        }
    }

    private Finding processSqlInjectionFinding(SemgrepFinding sf, LLMClient llmClient,
                                                String manifest, String vulnClass) {
        String vulnerableCode = readFileByPath(sf.getFilePath());
        if (vulnerableCode.startsWith("File not found")) {
            log.warn("[!] Could not read vulnerable class file: {}", sf.getFilePath());
            return null;
        }

        log.info("[*]   SQL injection detected in: {}", toRelativePath(sf.getFilePath()));

        StringBuilder userPrompt = new StringBuilder();
        userPrompt.append("=== SEMGREP FINDING ===\n");
        userPrompt.append("Rule: ").append(sf.getRuleId()).append("\n");
        userPrompt.append("File: ").append(sf.getFilePath()).append("\n");
        userPrompt.append("Line: ").append(sf.getLineNumber()).append("\n");
        userPrompt.append("Message: ").append(sf.getMessage()).append("\n");
        if (sf.getMetavars() != null && !sf.getMetavars().isEmpty()) {
            userPrompt.append("Metavariables:\n");
            sf.getMetavars().forEach((key, value) ->
                    userPrompt.append("  ").append(key).append(" = ").append(value).append("\n"));
        }
        userPrompt.append("\n");

        userPrompt.append("=== VULNERABLE CLASS CODE ===\n");
        userPrompt.append(vulnerableCode).append("\n\n");

        userPrompt.append("=== ANDROID MANIFEST ===\n");
        userPrompt.append(manifest).append("\n");

        try {
            String llmResponse = llmClient.chat(SQL_INJECTION_SYSTEM_PROMPT, userPrompt.toString());

            boolean isTruePositive = llmResponse.contains("TRUE_POSITIVE");
            String analysis = extractSection(llmResponse, "=== ANALYSIS ===", null);
            String llmVulnClass = extractSection(llmResponse, "=== VULNERABILITY CLASS ===", "=== POC ===");
            String llmPoc = extractSection(llmResponse, "=== POC ===", "=== ANALYSIS ===");

            log.info("[*]   Finding {}: {} - {}",
                    toRelativePath(sf.getFilePath()), isTruePositive ? "TRUE POSITIVE" : "FALSE POSITIVE",
                    llmVulnClass.isEmpty() ? vulnClass : llmVulnClass);

            String cleanPoc = null;
            if (isTruePositive) {
                if (!llmPoc.isEmpty() && !llmPoc.equalsIgnoreCase("N/A")) {
                    cleanPoc = llmPoc.trim();
                    cleanPoc = cleanPoc.replaceAll("```\\w*\\s*\\n", "").replaceAll("```", "").trim();
                }
                log.info("[*]   POC: {}", cleanPoc);
            }

            return Finding.builder()
                    .tool("semgrep")
                    .truePositive(isTruePositive)
                    .sourceFile(sf.getFilePath())
                    .sinkFile(sf.getFilePath())
                    .rawFlow(null)
                    .vulnerabilityClass(llmVulnClass.isEmpty() ? vulnClass : llmVulnClass)
                    .analysis(analysis)
                    .poc(cleanPoc)
                    .build();

        } catch (Exception e) {
            log.error("[!] LLM analysis failed for SQL injection finding: {}", e.getMessage());
            return Finding.builder()
                    .tool("semgrep")
                    .truePositive(false)
                    .sourceFile(sf.getFilePath())
                    .sinkFile(sf.getFilePath())
                    .rawFlow(null)
                    .vulnerabilityClass(vulnClass)
                    .analysis("LLM analysis failed: " + e.getMessage() + ". Manual review required.")
                    .poc(null)
                    .build();
        }
    }

    private String readFileByPath(String filePath) {
        try {
            Path path = Path.of(filePath);
            if (path.toFile().exists()) {
                return Files.readString(path);
            }
            String decompiledPath = PathUtils.getDecompiledApkPath();
            Path fullPath = Path.of(decompiledPath, "sources", filePath);
            if (fullPath.toFile().exists()) {
                return Files.readString(fullPath);
            }
            fullPath = Path.of(decompiledPath, filePath);
            if (fullPath.toFile().exists()) {
                return Files.readString(fullPath);
            }
            return "File not found: " + filePath;
        } catch (Exception e) {
            return "File not found: " + filePath;
        }
    }

    private String findAndReadJava(String className) {
        String decompiledPath = PathUtils.getDecompiledApkPath();
        String simpleClassName = className.contains(".")
                ? className.substring(className.lastIndexOf('.') + 1)
                : className;

        File sourcesDir = new File(decompiledPath, "sources");
        if (!sourcesDir.exists()) {
            return "Java file not found for: " + className;
        }

        List<File> candidates = new ArrayList<>();
        findFilesByName(sourcesDir, simpleClassName + ".java", candidates);

        if (candidates.isEmpty()) {
            return "Java file not found for: " + className;
        }

        if (className.contains(".")) {
            String[] originalParts = className.split("\\.");
            File bestMatch = null;
            int bestScore = -1;

            for (File candidate : candidates) {
                String candidateRelative = sourcesDir.toPath().relativize(candidate.toPath()).toString();
                String candidatePackage = candidateRelative.replace(File.separatorChar, '.').replace(".java", "");
                String[] candidateParts = candidatePackage.split("\\.");
                int score = 0;
                int minLen = Math.min(originalParts.length, candidateParts.length);
                for (int j = 0; j < minLen; j++) {
                    if (originalParts[j].equals(candidateParts[j])) score++;
                }
                if (score > bestScore) {
                    bestScore = score;
                    bestMatch = candidate;
                }
            }
            if (bestMatch != null) {
                try {
                    log.info("[*]   Found java (fuzzy): {}", toRelativePath(bestMatch.getPath()));
                    return Files.readString(bestMatch.toPath());
                } catch (Exception e) {
                    return "Java file not found for: " + className;
                }
            }
        }

        try {
            log.info("[*]   Found java: {}", toRelativePath(candidates.get(0).getPath()));
            return Files.readString(candidates.get(0).toPath());
        } catch (Exception e) {
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

    private String findAndReadManifest() {
        String decompiledPath = PathUtils.getDecompiledApkPath();
        String[] possiblePaths = {
                decompiledPath + "AndroidManifest.xml",
                decompiledPath + "resources/AndroidManifest.xml"
        };
        for (String path : possiblePaths) {
            File file = new File(path);
            if (file.exists()) {
                try {
                    return Files.readString(file.toPath());
                } catch (Exception e) {
                    return "Failed to read manifest";
                }
            }
        }
        return "AndroidManifest.xml not found";
    }

    private String toRelativePath(String absolutePath) {
        if (absolutePath == null) return "unknown";
        int idx = absolutePath.indexOf("decompiled_apks/");
        if (idx != -1) {
            return absolutePath.substring(idx + "decompiled_apks/".length());
        }
        idx = absolutePath.indexOf("sources/");
        if (idx != -1) {
            return absolutePath.substring(idx);
        }
        return absolutePath;
    }

    private String extractSection(String response, String startMarker, String endMarker) {
        int startIdx = response.indexOf(startMarker);
        if (startIdx == -1) return "";
        startIdx += startMarker.length();
        int endIdx = (endMarker != null) ? response.indexOf(endMarker, startIdx) : -1;
        String section = (endIdx != -1) ? response.substring(startIdx, endIdx) : response.substring(startIdx);
        return section.trim();
    }

    private String extractPackageFromManifest(String manifest) {
        if (manifest == null || manifest.isBlank()) return "com.unknown.app";
        int pkgIdx = manifest.indexOf("package=\"");
        if (pkgIdx == -1) return "com.unknown.app";
        int start = pkgIdx + "package=\"".length();
        int end = manifest.indexOf("\"", start);
        if (end == -1) return "com.unknown.app";
        return manifest.substring(start, end).trim();
    }

    private String mapRuleToVulnClass(String ruleId) {
        if (ruleId == null) return "Unknown";
        if (ruleId.contains("dynamic-receiver")) {
            return "Dynamic Broadcast Receiver";
        }
        if (ruleId.contains("sql-injection")) {
            return "SQL Injection";
        }
        return "Semgrep: " + ruleId;
    }

    private int rulePriority(String ruleId) {
        if (ruleId == null) return 99;
        if (ruleId.contains("exported-flag") || ruleId.contains("exported-constant")) return 30;
        if (ruleId.contains("anon")) return 20;
        if (ruleId.contains("dynamic-receiver")) return 10;
        if (ruleId.contains("sql-injection")) return 15;
        return 50;
    }
}
