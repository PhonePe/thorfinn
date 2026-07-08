package com.thorfinn.verification;

import com.thorfinn.device.DeviceManager;
import com.thorfinn.device.NetworkCapture;
import com.thorfinn.models.Finding;
import com.thorfinn.models.VerificationResult;
import com.thorfinn.utils.CommandRunner;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class AdbVerifier implements Verification {

    private static final int POST_POC_WAIT_SECONDS = 30;

    private static final Pattern SU_C_PATTERN =
            Pattern.compile("adb\\s+shell\\s+su\\s+(?:0\\s+)?-c\\s+(['\"])(.*?)\\1");

    private final NetworkCapture networkCapture = new NetworkCapture();
    private final String packageName;
    private final PocApprovalMode pocMode;
    private final Scanner scanner;

    public AdbVerifier(String packageName, PocApprovalMode pocMode) {
        this.packageName = packageName;
        this.pocMode = pocMode;
        this.scanner = (pocMode == PocApprovalMode.INTERACTIVE) ? new Scanner(System.in) : null;
    }

    @Override
    public VerificationResult verify(Finding finding) throws Exception {
        String command = normalizeRootCommand(finding.getPoc());
        String vulnClass = finding.getVulnerabilityClass() != null ? finding.getVulnerabilityClass().toLowerCase().trim() : "";
        log.info("[*] AdbVerifier: Executing POC for {} -> {} [{}]", finding.getSourceFile(), finding.getSinkFile(), vulnClass);
        log.info("[*] AdbVerifier: Command: {}", command);

        if (command != null && command.startsWith("NO_ADB_COMMAND")) {
            log.info("[*] AdbVerifier: Non-adb POC detected - storing as evidence for manual review");
            return VerificationResult.builder()
                    .finding(finding)
                    .status("MANUAL_VERIFICATION")
                    .commandExecuted("N/A - requires attacker app (see evidence)")
                    .output(command)
                    .evidence(List.of(command))
                    .build();
        }

        if (!approveCommand(command, finding)) {
            log.info("[*] AdbVerifier: Command SKIPPED by user/policy");
            return VerificationResult.builder()
                    .finding(finding)
                    .truePositive(true)
                    .status("SKIPPED")
                    .commandExecuted(command)
                    .build();
        }

        forceStopApp();

        switch (vulnClass) {
            case "webview vulnerability" -> {
                return verifyWebView(finding, command);
            }
            case "intent redirection" -> {
                return verifyIntentRedirection(finding, command);
            }
            case "dynamic broadcast receiver" -> {
                return verifyDynamicReceiver(finding, command);
            }
            default -> {
                return verifyDefault(finding, command);
            }
        }
    }

    private boolean approveCommand(String command, Finding finding) {
        if (pocMode == PocApprovalMode.AUTO_APPROVE) {
            log.info("[*] AdbVerifier: Auto-approved (--auto-approve)");
            return true;
        }
        if (pocMode == PocApprovalMode.SKIP) {
            log.info("[*] AdbVerifier: Auto-skipped (--skip-verify)");
            return false;
        }
        printPocReviewBox(command, finding);
        System.out.print("[?] Execute this command on device? (Y/N): ");
        System.out.flush();
        String input = scanner.nextLine().trim();
        return input.equalsIgnoreCase("Y");
    }

    /** Inner width (number of chars between the vertical borders) of the review box. */
    private static final int BOX_WIDTH = 78;

    /** Renders a properly aligned box that pads short lines and wraps long ones. */
    private void printPocReviewBox(String command, Finding finding) {
        StringBuilder sb = new StringBuilder("\n");
        sb.append(boxBorder('╔', '╗'));
        sb.append(boxCentered("LLM-GENERATED POC - REVIEW BEFORE EXECUTION"));
        sb.append(boxBorder('╠', '╣'));
        boxField(sb, "Vulnerability", nvl(finding.getVulnerabilityClass(), "Unknown"));
        boxField(sb, "Source", nvl(finding.getSourceFile(), "N/A"));
        boxField(sb, "Sink", nvl(finding.getSinkFile(), "N/A"));
        sb.append(boxBorder('╠', '╣'));
        sb.append(boxLine(" Command:"));
        for (String part : wrap(command, BOX_WIDTH - 3)) {
            sb.append(boxLine("   " + part));
        }
        sb.append(boxBorder('╚', '╝'));
        System.out.print(sb);
    }

    private static String nvl(String value, String fallback) {
        return value != null ? value : fallback;
    }

    private static String boxBorder(char left, char right) {
        return left + "═".repeat(BOX_WIDTH) + right + "\n";
    }

    private static String boxLine(String text) {
        if (text.length() > BOX_WIDTH) {
            text = text.substring(0, BOX_WIDTH);
        }
        return "║" + text + " ".repeat(BOX_WIDTH - text.length()) + "║\n";
    }

    private static String boxCentered(String text) {
        if (text.length() > BOX_WIDTH) {
            text = text.substring(0, BOX_WIDTH);
        }
        int padding = BOX_WIDTH - text.length();
        int left = padding / 2;
        return "║" + " ".repeat(left) + text + " ".repeat(padding - left) + "║\n";
    }

    private static void boxField(StringBuilder sb, String label, String value) {
        String prefix = " " + padRight(label, 13) + ": ";
        List<String> parts = wrap(value, BOX_WIDTH - prefix.length());
        sb.append(boxLine(prefix + parts.get(0)));
        String indent = " ".repeat(prefix.length());
        for (int i = 1; i < parts.size(); i++) {
            sb.append(boxLine(indent + parts.get(i)));
        }
    }

    private static String padRight(String text, int width) {
        return text.length() >= width ? text : text + " ".repeat(width - text.length());
    }

    private static List<String> wrap(String text, int width) {
        List<String> lines = new ArrayList<>();
        String remaining = text != null ? text : "";
        while (remaining.length() > width) {
            lines.add(remaining.substring(0, width));
            remaining = remaining.substring(width);
        }
        lines.add(remaining);
        return lines;
    }

    private VerificationResult verifyIntentRedirection(Finding finding, String command) throws Exception {
        log.info("[*] AdbVerifier: Intent Redirection finding - executing POC to access protected component");

        try {
            String output = CommandRunner.run(command);

            log.info("[*] AdbVerifier: Waiting {}s for device side-effects...", POST_POC_WAIT_SECONDS);
            Thread.sleep(POST_POC_WAIT_SECONDS * 1000L);

            List<String> evidence = List.of(output != null ? output : "");

            boolean hasError = output != null && (
                    output.contains("SecurityException") ||
                    output.contains("Permission Denial") ||
                    output.contains("not exported") ||
                    output.contains("requires a permission") ||
                    output.contains("not allowed") ||
                    output.contains("java.lang.SecurityException") ||
                    output.contains("Error")
            );

            String status = hasError ? "EXECUTED_NO_EVIDENCE" : "EXECUTED";
            log.info("[*] AdbVerifier: Intent Redirection status={} (error indicators found={})", status, hasError);

            return VerificationResult.builder()
                    .finding(finding)
                    .status(status)
                    .commandExecuted(command)
                    .output(output)
                    .evidence(evidence)
                    .build();

        } catch (Exception e) {
            log.error("[!] AdbVerifier: Intent Redirection POC failed: {}", e.getMessage());
            return VerificationResult.builder()
                    .finding(finding)
                    .status("ERROR")
                    .commandExecuted(command)
                    .output(e.getMessage())
                    .errorMessage(e.getMessage())
                    .evidence(List.of(e.getMessage() != null ? e.getMessage() : ""))
                    .build();
        }
    }

    private VerificationResult verifyWebView(Finding finding, String command) throws Exception {
        clearAppData();

        log.info("[*] AdbVerifier: WebView finding - starting network capture");
        networkCapture.startCapture();

        try {
            String output = CommandRunner.run(command);

            log.info("[*] AdbVerifier: Waiting {}s for device side-effects...", POST_POC_WAIT_SECONDS);
            Thread.sleep(POST_POC_WAIT_SECONDS * 1000L);

            List<String> evidence = networkCapture.stopAndExtractRequests();
            log.info("[*] AdbVerifier: Captured {} network request(s) as evidence", evidence.size());

            String status = evidence.isEmpty() ? "EXECUTED_NO_EVIDENCE" : "EXECUTED";

            return VerificationResult.builder()
                    .finding(finding)
                    .status(status)
                    .commandExecuted(command)
                    .output(output)
                    .evidence(evidence)
                    .build();

        } catch (Exception e) {
            log.error("[!] AdbVerifier: POC failed: {}", e.getMessage());
            List<String> evidence = networkCapture.stopAndExtractRequests();

            return VerificationResult.builder()
                    .finding(finding)
                    .status("ERROR")
                    .commandExecuted(command)
                    .output(e.getMessage())
                    .errorMessage(e.getMessage())
                    .evidence(evidence)
                    .build();
        }
    }

    private VerificationResult verifyDynamicReceiver(Finding finding, String command) throws Exception {
        log.info("[*] AdbVerifier: Dynamic Receiver finding - launching app via monkey to register receiver");
        try {
            String monkeyCmd = "adb shell monkey -p " + packageName + " -c android.intent.category.LAUNCHER 1";
            log.info("[*] AdbVerifier: Launching app: {}", monkeyCmd);
            String monkeyOutput = CommandRunner.runArgs("adb", "shell", "monkey", "-p", packageName, "-c", "android.intent.category.LAUNCHER", "1");
            log.info("[*] AdbVerifier: Monkey output: {}", monkeyOutput);

            log.info("[*] AdbVerifier: Waiting 5s for receiver registration...");
            Thread.sleep(5000L);

            log.info("[*] AdbVerifier: Sending broadcast: {}", command);
            String broadcastOutput = CommandRunner.run(command);
            log.info("[*] AdbVerifier: Broadcast output: {}", broadcastOutput);

            log.info("[*] AdbVerifier: Waiting {}s for device side-effects...", POST_POC_WAIT_SECONDS);
            Thread.sleep(POST_POC_WAIT_SECONDS * 1000L);

            List<String> evidence = List.of(
                    "Monkey launch: " + (monkeyOutput != null ? monkeyOutput : "(no output)"),
                    "Broadcast output: " + (broadcastOutput != null ? broadcastOutput : "(no output)")
            );
            log.info("[*] AdbVerifier: Broadcast output logged as evidence");

            String status = (broadcastOutput != null && !broadcastOutput.isBlank()) ? "EXECUTED" : "EXECUTED_NO_EVIDENCE";

            return VerificationResult.builder()
                    .finding(finding)
                    .status(status)
                    .commandExecuted(monkeyCmd + " && sleep 5 && " + command)
                    .output(broadcastOutput)
                    .evidence(evidence)
                    .build();

        } catch (Exception e) {
            log.error("[!] AdbVerifier: Dynamic Receiver POC failed: {}", e.getMessage());
            return VerificationResult.builder()
                    .finding(finding)
                    .status("ERROR")
                    .commandExecuted(command)
                    .output(e.getMessage())
                    .errorMessage(e.getMessage())
                    .evidence(List.of(e.getMessage() != null ? e.getMessage() : ""))
                    .build();
        }
    }

    private VerificationResult verifyDefault(Finding finding, String command) throws Exception {
        try {
            String output = CommandRunner.run(command);

            log.info("[*] AdbVerifier: Waiting {}s for device side-effects...", POST_POC_WAIT_SECONDS);
            Thread.sleep(POST_POC_WAIT_SECONDS * 1000L);

            return VerificationResult.builder()
                    .finding(finding)
                    .status("EXECUTED")
                    .commandExecuted(command)
                    .output(output)
                    .build();

        } catch (Exception e) {
            log.error("[!] AdbVerifier: POC failed: {}", e.getMessage());
            return VerificationResult.builder()
                    .finding(finding)
                    .status("ERROR")
                    .commandExecuted(command)
                    .output(e.getMessage())
                    .errorMessage(e.getMessage())
                    .build();
        }
    }

    private void forceStopApp() throws Exception {
        log.info("[*] AdbVerifier: Force-stopping app: {}", packageName);
        CommandRunner.runArgs("adb", "shell", "am", "force-stop", packageName);
        log.info("[*] AdbVerifier: App stopped");
    }

    private void clearAppData() {
        try {
            log.info("[*] AdbVerifier: Clearing app data/cache for fresh WebView load: {}", packageName);
            CommandRunner.runArgs("adb", "shell", "pm", "clear", packageName);
        } catch (Exception e) {
            log.warn("[!] AdbVerifier: Failed to clear app data ({}): proceeding anyway", e.getMessage());
        }
    }

    static String normalizeRootCommand(String command) {
        if (command == null || command.isBlank() || !DeviceManager.isEmulatorRoot()) {
            return command;
        }
        Matcher matcher = SU_C_PATTERN.matcher(command);
        if (matcher.find()) {
            String quote = matcher.group(1);
            String inner = matcher.group(2);
            String rewritten = command.substring(0, matcher.start())
                    + "adb shell " + quote + inner + quote
                    + command.substring(matcher.end());
            log.info("[*] AdbVerifier: Emulator root detected - rewrote 'su -c' POC to run directly: {}", rewritten);
            return rewritten;
        }
        return command;
    }
}
