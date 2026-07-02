package com.thorfinn.orchestrator;

import com.thorfinn.analysis.ManifestAnalyzer;
import com.thorfinn.config.Config;
import com.thorfinn.config.ConfigContext;
import com.thorfinn.config.ConfigLoader;
import com.thorfinn.decompilers.ApkTool;
import com.thorfinn.decompilers.JADXTool;
import com.thorfinn.device.DeviceManager;
import com.thorfinn.models.Finding;
import com.thorfinn.models.ManifestInfo;
import com.thorfinn.models.VerificationResult;
import com.thorfinn.poc.TaiEPOC;
import com.thorfinn.poc.PermissionCheckerPOC;
import com.thorfinn.poc.SemgrepPOC;
import com.thorfinn.poc.TruffleHogPOC;
import com.thorfinn.poc.poc;
import com.thorfinn.report.HtmlReportGenerator;
import com.thorfinn.tools.TaiE;
import com.thorfinn.tools.PermissionChecker;
import com.thorfinn.tools.Semgrep;
import com.thorfinn.tools.TruffleHog;
import com.thorfinn.tools.Tools;
import com.thorfinn.utils.CommandRunner;
import com.thorfinn.utils.PathUtils;
import com.thorfinn.verification.AdbVerifier;
import com.thorfinn.verification.PocApprovalMode;
import lombok.extern.slf4j.Slf4j;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

@Slf4j
public class  Orchestrator {

    private static final String BANNER = """
           
               ████████╗██╗  ██╗ ██████╗ ██████╗ ███████╗██╗███╗   ██╗███╗   ██╗
               ╚══██╔══╝██║  ██║██╔═══██╗██╔══██╗██╔════╝██║████╗  ██║████╗  ██║
                  ██║   ████████║██║   ██║██████╔╝█████╗  ██║██╔██╗ ██║██╔██╗ ██║
                  ██║   ██╔══██║██║   ██║██╔══██╗██╔══╝  ██║██║╚██╗██║██║╚██╗██║
                  ██║   ██║  ██║╚██████╔╝██║  ██║██║     ██║██║ ╚████║██║ ╚████║
                  ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝
            """;

    private String packageName;
    private PocApprovalMode pocMode;

    public void execute(String packageName, int timeLimit, String configPath, PocApprovalMode pocMode) throws Exception {
        CommandRunner.validatePackageName(packageName);
        this.packageName = packageName;
        this.pocMode = pocMode;
        Config config = ConfigLoader.loadConfig(configPath);
        config.getToolsConfig().setCpgTimeLimit(timeLimit);
        ConfigContext.setConfig(config);
        printBanner();
        log.info("[*] Starting Thorfinn Pipeline for package: {} (CPG time-limit: {}s)", packageName, timeLimit);
        CommandRunner.deleteContentsOfFolder(Paths.get(PathUtils.getOutputPath()));
        log.info("[*] Step 0: Setting up — extracting APK from device...");
        setupAndExtractApk(config);
        log.info("[*] Step 1: Decompiling APK...");
        decompileApk(config);
        log.info("[*] Step 2: Analyzing AndroidManifest.xml...");
        ManifestAnalyzer manifestAnalyzer = new ManifestAnalyzer();
        ManifestInfo manifestInfo = manifestAnalyzer.analyze();
        log.info("[*] Step 3: Executing Tools");
        executeTools(config);
        log.info("[*] Step 4: POC creation and false positive filtering");
        List<Finding> allFindings = generatePOCs(config);
        log.info("[*] Step 5: Verifying POCs on device...");
        List<VerificationResult> results = verifyFindings(allFindings);
        log.info("[*] Step 6: Generating HTML report...");
        HtmlReportGenerator reportGenerator = new HtmlReportGenerator();
        reportGenerator.generateReport(results, manifestInfo);
        log.info("[*] Pipeline complete. Total confirmed findings: {}, Verified: {}", allFindings.size(), results.size());
    }

    private void printBanner() {
        log.info(BANNER);
    }

    private void setupAndExtractApk(Config config) throws Exception {

        DeviceManager deviceManager = new DeviceManager();
        deviceManager.checkDeviceConnected();


        log.info("[*] Resolving APK path for package: {}", packageName);
        String pmOutput = CommandRunner.runArgs("adb", "shell", "pm", "path", packageName);

        String deviceApkPath = null;
        for (String line : pmOutput.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.startsWith("package:")) {
                deviceApkPath = trimmed.substring("package:".length());
                break;
            }
        }
        if (deviceApkPath == null || deviceApkPath.isBlank()) {
            throw new RuntimeException("Package not found on device: " + packageName
                    + ". Make sure the app is installed. Output: " + pmOutput);
        }
        log.info("[*] APK found on device: {}", deviceApkPath);


        String baseDir = PathUtils.getBaseDirectory();
        Path apkDir = Paths.get(baseDir, "resources", "apk");
        if (Files.exists(apkDir)) {
            log.info("[*] Cleaning existing apk directory: {}", apkDir);
            CommandRunner.deleteContentsOfFolder(apkDir);
        }
        Files.createDirectories(apkDir);

        String localApkName = packageName + ".apk";
        Path localApkPath = apkDir.resolve(localApkName);

        log.info("[*] Pulling APK to: {}", localApkPath);
        CommandRunner.runArgs("adb", "pull", deviceApkPath, localApkPath.toAbsolutePath().toString());
        log.info("[*] APK pulled successfully: {}", localApkPath);


        config.getPathConfigs().setApkPath(localApkPath.toAbsolutePath().toString());
        log.info("[*] Setup complete. APK ready at: {}", localApkPath);
    }

    private void decompileApk(Config config) throws Exception {

        Path decompiledDir = Paths.get(PathUtils.getDecompiledApkPath());
        if (Files.exists(decompiledDir)) {
            log.info("[*] Cleaning existing decompiled_apks directory: {}", decompiledDir);
            CommandRunner.deleteContentsOfFolder(decompiledDir);
        }

        if(config.getToolsConfig().getDecompilers().equals("apktool")){
            ApkTool apkTool = new ApkTool();
            apkTool.decompileApk(PathUtils.getApkPath(), PathUtils.getDecompiledApkPath());
        } else if(config.getToolsConfig().getDecompilers().equals("jadx")){
            JADXTool jadxTool = new JADXTool();
            jadxTool.decompileApk(PathUtils.getApkPath(), PathUtils.getDecompiledApkPath());
        }
    }

    private void executeTools(Config config) throws Exception {
        List<String> toolsToExecute = config.getToolsConfig().getAnalysisTools();
        for (String tool : toolsToExecute) {
            try {
                switch (tool) {
                    case "taie" -> {
                        Tools taie = new TaiE();
                        taie.execute();
                    }
                    case "permissionChecker" -> {
                        Tools permissionChecker = new PermissionChecker();
                        permissionChecker.execute();
                    }
                    case "truffleHog" -> {
                        Tools truffleHog = new TruffleHog();
                        truffleHog.execute();
                    }
                    case "semgrep" -> {
                        Tools semgrep = new Semgrep();
                        semgrep.execute();
                    }
                    default -> log.warn("[!] Unknown tool: {}", tool);
                }
            } catch (Throwable t) {
                log.error("[!] Tool '{}' failed with error: {} — continuing with remaining tools", tool, t.getMessage());
                log.debug("[!] Stack trace for tool '{}' failure:", tool, t);
            }
        }
    }

    private List<Finding> generatePOCs(Config config) throws Exception {
        List<Finding> allFindings = new java.util.ArrayList<>();
        List<String> toolsToParse = config.getToolsConfig().getAnalysisTools();
        for (String tool : toolsToParse) {
            try {
                switch (tool) {
                    case "taie" -> {
                        poc taiePOC = new TaiEPOC();
                        allFindings.addAll(taiePOC.generateFindings());
                    }
                    case "permissionChecker" -> {
                        poc permPOC = new PermissionCheckerPOC();
                        allFindings.addAll(permPOC.generateFindings());
                    }
                    case "truffleHog" -> {
                        poc truffleHogPOC = new TruffleHogPOC();
                        allFindings.addAll(truffleHogPOC.generateFindings());
                    }
                    case "semgrep" -> {
                        poc semgrepPOC = new SemgrepPOC();
                        allFindings.addAll(semgrepPOC.generateFindings());
                    }
                    default -> log.warn("[!] No POC generator for tool: {}", tool);
                }
            } catch (Throwable t) {
                log.error("[!] POC generation for '{}' failed: {} — continuing with remaining tools", tool, t.getMessage());
                log.debug("[!] Stack trace for POC '{}' failure:", tool, t);
            }
        }
        return allFindings;
    }

    private List<VerificationResult> verifyFindings(List<Finding> findings) throws Exception {
        AdbVerifier adbVerifier = new AdbVerifier(packageName, pocMode);
        List<VerificationResult> results = new ArrayList<>();

        for (Finding finding : findings) {

            if (!finding.isTruePositive()) {
                log.info("[*] Finding [{} -> {}]: FALSE_POSITIVE — skipping verification",
                        finding.getSourceFile(), finding.getSinkFile());
                results.add(VerificationResult.builder()
                        .finding(finding)
                        .truePositive(false)
                        .status("FALSE_POSITIVE")
                        .build());
                continue;
            }

            String poc = finding.getPoc();
            if (poc != null && poc.trim().startsWith("adb")) {
                try {
                    VerificationResult result = adbVerifier.verify(finding);
                    result.setTruePositive(true);
                    results.add(result);
                    log.info("[*] Finding [{} -> {}]: {} (evidence: {} item(s))",
                            finding.getSourceFile(), finding.getSinkFile(), result.getStatus(),
                            result.getEvidence() != null ? result.getEvidence().size() : 0);
                } catch (Throwable t) {
                    log.error("[!] Verification failed for [{} -> {}]: {} — continuing",
                            finding.getSourceFile(), finding.getSinkFile(), t.getMessage());
                    results.add(VerificationResult.builder()
                            .finding(finding)
                            .truePositive(true)
                            .status("ERROR")
                            .errorMessage("Verification failed: " + t.getMessage())
                            .build());
                }
            } else {
                log.warn("[!] Skipping finding with unsupported POC type: {}", poc);
                results.add(VerificationResult.builder()
                        .finding(finding)
                        .truePositive(true)
                        .status("SKIPPED")
                        .commandExecuted(poc)
                        .build());
            }
        }
        return results;
    }
}
