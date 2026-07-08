package com.thorfinn.parsers;

import com.thorfinn.config.ConfigContext;
import com.thorfinn.models.TaiEResult;
import com.thorfinn.models.TaiEResult.TaintFlowInfo;
import com.thorfinn.utils.PathUtils;
import lombok.extern.slf4j.Slf4j;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class TaiEParser implements Parsers<TaiEResult> {

    private static final Pattern TAINT_FLOW_PATTERN = Pattern.compile("TaintFlow\\{(.+?)\\s*->\\s*(.+?)\\}");
    private static final Pattern ENTRY_PATTERN = Pattern.compile("<([^:]+):.+?>\\s*\\[\\d+@L-?\\d+]");
    private static final Pattern FLOW_COUNT_PATTERN = Pattern.compile("Detected\\s+(\\d+)\\s+taint flow\\(s\\)");

    private static final List<String> IGNORED_PACKAGES = new ArrayList<>(Arrays.asList(
            "com.google.",
            "com.facebook.",
            "com.firebase.",
            "com.crashlytics.",
            "com.android.",
            "android.",
            "androidx.",
            "kotlin.",
            "kotlinx.",
            "io.fabric.",
            "io.flutter.",
            "io.reactivex.",
            "io.realm.",
            "com.squareup.",
            "com.bumptech.",
            "com.airbnb.",
            "com.jakewharton.",
            "org.apache.",
            "org.json.",
            "org.xmlpull.",
            "okhttp3.",
            "okio.",
            "retrofit2.",
            "dagger.",
            "javax.",
            "bolts.",
            "es.voghdev.",
            "com.adjust.",
            "com.appsflyer.",
            "com.braze.",
            "com.clevertap.",
            "com.mixpanel.",
            "com.segment.",
            "com.newrelic.",
            "com.datadog.",
            "com.rokt.",
            "com.razorpay.",
            "com.moe",
            "org.jsoup.",
            "com.netcore.",
            "HtmlViewHolder",
            "io.sentry.",
            "com.freshchat.",
            "com.webengage.",
            "expo.",
            "in.juspay.",
            "io.branch.",
            "io.invertase.",
            "com.pairip.",
            "com.stripe.",
            "com.braintreepayments.",
            "com.amazonaws.",
            "com.microsoft.",
            "com.amazon.",
            "org.bouncycastle.",
            "com.mappls."
    ));

    @Override
    public TaiEResult parse() throws Exception {
        List<String> extra = ConfigContext.getConfig().getToolsConfig().getIgnoredPackages();
        if (extra != null && !extra.isEmpty()) {
            IGNORED_PACKAGES.addAll(extra);
            log.info("[*] Added {} additional ignored package(s) from config", extra.size());
        }

        String taieOutputFile = Paths.get(PathUtils.getOutputPath(), "taie_output.txt").toString();
        String fileContent = readFile(taieOutputFile);

        int totalFlows = extractFlowCount(fileContent);
        List<TaintFlowInfo> taintFlows = extractTaintFlows(fileContent);

        if (totalFlows != taintFlows.size()) {
            log.warn("[!] Flow count mismatch: reported={}, parsed={}", totalFlows, taintFlows.size());
        }

        enrichWithTaintFlowGraph(taintFlows);

        TaiEResult result = TaiEResult.builder()
                .totalFlowsDetected(totalFlows)
                .taintFlows(taintFlows)
                .build();

        log.info("[*] Parsed {} taint flow(s)", taintFlows.size());
        for (int i = 0; i < taintFlows.size(); i++) {
            TaintFlowInfo flow = taintFlows.get(i);
            log.info("[*]   Flow {}: {} -> {}", i + 1,
                    flow.getSourceFile(),
                    flow.getSinkFile());
            if (flow.getIntermediateClasses() != null && !flow.getIntermediateClasses().isEmpty()) {
                log.info("[*]     Intermediate classes: {}", flow.getIntermediateClasses());
            }
            if (flow.getFlowDescription() != null) {
                log.info("[*]     Flow path: {}", flow.getFlowDescription());
            }
        }

        saveFindings(result);

        return result;
    }

    private String readFile(String filePath) throws Exception {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(Paths.get(filePath).toFile()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        }
        return content.toString();
    }

    private int extractFlowCount(String output) {
        Matcher matcher = FLOW_COUNT_PATTERN.matcher(output);
        if (matcher.find()) {
            return Integer.parseInt(matcher.group(1));
        }
        log.warn("[!] Could not extract taint flow count from output");
        return 0;
    }

    private List<TaintFlowInfo> extractTaintFlows(String output) {
        List<TaintFlowInfo> flows = new ArrayList<>();
        Set<String> seenPairs = new HashSet<>();
        String[] lines = output.split("\n");

        for (String line : lines) {
            String trimmed = line.trim();
            if (!trimmed.contains("TaintFlow{")) {
                continue;
            }

            Matcher flowMatcher = TAINT_FLOW_PATTERN.matcher(trimmed);
            if (!flowMatcher.find()) {
                log.warn("[!] Failed to parse taint flow line: {}", trimmed);
                continue;
            }

            String sourcePart = flowMatcher.group(1).trim();
            String sinkPart = flowMatcher.group(2).trim();

            Matcher sourceMatcher = ENTRY_PATTERN.matcher(sourcePart);
            Matcher sinkMatcher = ENTRY_PATTERN.matcher(sinkPart);

            if (!sourceMatcher.find() || !sinkMatcher.find()) {
                log.warn("[!] Failed to parse source/sink from line: {}", trimmed);
                continue;
            }

            String sourceClass = sourceMatcher.group(1).trim();
            String sinkClass = sinkMatcher.group(1).trim();

            if (isIgnoredPackage(sourceClass) || isIgnoredPackage(sinkClass)) {
                log.info("[*] Skipping third-party flow: {} -> {}", sourceClass, sinkClass);
                continue;
            }

            String dedupeKey = trimmed;
            if (seenPairs.contains(dedupeKey)) {
                log.info("[*] Skipping exact duplicate flow: {} -> {}", sourceClass, sinkClass);
                continue;
            }
            seenPairs.add(dedupeKey);

            flows.add(TaintFlowInfo.builder()
                    .sourceFile(sourceClass)
                    .sinkFile(sinkClass)
                    .rawFlow(trimmed)
                    .build());
        }

        return flows;
    }

    private boolean isIgnoredPackage(String className) {
        for (String prefix : IGNORED_PACKAGES) {
            if (className.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private void enrichWithTaintFlowGraph(List<TaintFlowInfo> taintFlows) {
        try {
            String dotFilePath = PathUtils.getTaiEOutputPath() + "/taint-flow-graph.dot";
            Path dotPath = Path.of(dotFilePath);
            if (!Files.exists(dotPath)) {
                log.warn("[!] Taint flow graph file not found at: {} - skipping TFG enrichment", dotFilePath);
                return;
            }

            TaintFlowGraphParser tfgParser = new TaintFlowGraphParser();
            TaintFlowGraphParser.ParsedGraph graph = tfgParser.parseGraph(dotFilePath);

            if (graph == null) {
                log.warn("[!] Failed to parse TFG - skipping enrichment");
                return;
            }

            int enriched = 0;
            for (TaintFlowInfo flow : taintFlows) {
                TaintFlowGraphParser.TfgFlowData flowData = tfgParser.findFlowPath(
                        graph, flow.getSourceFile(), flow.getSinkFile());

                if (flowData != null) {
                    flow.setFlowPath(flowData.orderedPath());
                    flow.setIntermediateClasses(flowData.intermediateClasses());
                    flow.setAllInvolvedClasses(flowData.allInvolvedClasses());
                    flow.setFlowDescription(flowData.flowDescription());
                    enriched++;
                    log.info("[*] TFG: Enriched flow {} -> {} with {} intermediate class(es): {}",
                            flow.getSourceFile(), flow.getSinkFile(),
                            flowData.intermediateClasses().size(),
                            flowData.intermediateClasses());
                } else {
                    log.warn("[*] TFG: No path found in graph for flow {} -> {}",
                            flow.getSourceFile(), flow.getSinkFile());
                }
            }

            log.info("[*] TFG enrichment complete: {}/{} flows enriched with propagation paths",
                    enriched, taintFlows.size());

        } catch (Exception e) {
            log.warn("[!] Failed to parse taint-flow-graph: {} - continuing without TFG data", e.getMessage());
        }
    }

    public void saveFindings(TaiEResult taieResult) {
        String outputPath = Paths.get(PathUtils.getOutputPath(), "potential_taie_findings.txt").toString();
        try (FileWriter writer = new FileWriter(outputPath)) {
            writer.write("=== TaiE Taint Analysis Findings ===\n");
            writer.write("Total taint flows detected: " + taieResult.getTotalFlowsDetected() + "\n\n");

            List<TaintFlowInfo> flows = taieResult.getTaintFlows();
            for (int i = 0; i < flows.size(); i++) {
                TaintFlowInfo flow = flows.get(i);
                writer.write("--- Flow " + (i + 1) + " ---\n");
                writer.write("Source File : " + flow.getSourceFile() + "\n");
                writer.write("Sink File   : " + flow.getSinkFile() + "\n");
                writer.write("Raw Flow    : " + flow.getRawFlow() + "\n");
                if (flow.getIntermediateClasses() != null && !flow.getIntermediateClasses().isEmpty()) {
                    writer.write("Intermediate Classes: " + String.join(", ", flow.getIntermediateClasses()) + "\n");
                }
                if (flow.getAllInvolvedClasses() != null && !flow.getAllInvolvedClasses().isEmpty()) {
                    writer.write("All Involved Classes: " + String.join(", ", flow.getAllInvolvedClasses()) + "\n");
                }
                if (flow.getFlowDescription() != null && !flow.getFlowDescription().isEmpty()) {
                    writer.write("Taint Flow Path: " + flow.getFlowDescription() + "\n");
                }
                writer.write("\n");
            }

            log.info("[*] Findings saved to: {}", outputPath);
        } catch (Exception e) {
            log.error("[!] Failed to save findings: {}", e.getMessage());
        }
    }
}
