package com.thorfinn.device;

import com.thorfinn.utils.CommandRunner;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;

@Slf4j
public class NetworkCapture {

    private static final String DNS_LOG_PATH = "/sdcard/thorfinn_dns.txt";

    private String previousPrivateDnsMode = null;

    public void startCapture() {
        try {
            disablePrivateDns();

            flushDnsCache();

            runQuietly(DeviceManager.rootShellCommand("rm -f " + DNS_LOG_PATH));

            CommandRunner.run(DeviceManager.rootShellCommand("nohup tcpdump -i any -n -l port 53 or port 853 > " + DNS_LOG_PATH + " 2>&1 &"));

            Thread.sleep(2000);

            log.info("[*] NetworkCapture: DNS capture started — logging to {}", DNS_LOG_PATH);

        } catch (Exception e) {
            log.warn("[!] NetworkCapture: Failed to start DNS capture: {}", e.getMessage());
        }
    }

    public List<String> stopAndExtractRequests() {
        List<String> evidence = new ArrayList<>();
        try {
            try {
                CommandRunner.run(DeviceManager.rootShellCommand("pkill -2 tcpdump"));
            } catch (Exception e) {
                try {
                    CommandRunner.run(DeviceManager.rootShellCommand("pkill -9 tcpdump"));
                } catch (Exception ignored) {}
            }

            Thread.sleep(2000);

            String fileContent = "";
            try {
                fileContent = CommandRunner.run(DeviceManager.rootShellCommand("cat " + DNS_LOG_PATH));
            } catch (Exception e) {
                log.warn("[!] NetworkCapture: Failed to read DNS log file: {}", e.getMessage());
            }

            if (fileContent != null && !fileContent.isBlank()) {
                for (String line : fileContent.split("\n")) {
                    String trimmed = line.trim();
                    if (trimmed.isEmpty()
                            || trimmed.startsWith("tcpdump:")
                            || trimmed.startsWith("listening on")
                            || trimmed.contains("packets captured")
                            || trimmed.contains("packets received")
                            || trimmed.contains("packets dropped")) {
                        continue;
                    }
                    evidence.add(trimmed);
                }
            }

            for (String line : evidence) {
                log.info("[dns-evidence] {}", line);
            }

            runQuietly(DeviceManager.rootShellCommand("rm -f " + DNS_LOG_PATH));

            log.info("[*] NetworkCapture: Captured {} DNS evidence line(s)", evidence.size());
        } catch (Exception e) {
            log.warn("[!] NetworkCapture: Failed to stop/extract DNS capture: {}", e.getMessage());
        } finally {
            restorePrivateDns();
        }
        return evidence;
    }

    private void disablePrivateDns() {
        try {
            previousPrivateDnsMode = CommandRunner.run(
                    DeviceManager.rootShellCommand("settings get global private_dns_mode")).trim();
            log.info("[*] NetworkCapture: Current Private DNS mode: {}", previousPrivateDnsMode);
        } catch (Exception e) {
            previousPrivateDnsMode = null;
            log.debug("[*] NetworkCapture: Could not read Private DNS mode: {}", e.getMessage());
        }

        if (previousPrivateDnsMode != null && previousPrivateDnsMode.equalsIgnoreCase("off")) {
            return;
        }

        log.info("[*] NetworkCapture: Disabling Private DNS to force plaintext resolution");
        runQuietly(DeviceManager.rootShellCommand("settings put global private_dns_mode off"));
    }

    private void restorePrivateDns() {
        if (previousPrivateDnsMode == null
                || previousPrivateDnsMode.isBlank()
                || previousPrivateDnsMode.equalsIgnoreCase("null")
                || previousPrivateDnsMode.equalsIgnoreCase("off")) {
            previousPrivateDnsMode = null;
            return;
        }

        log.info("[*] NetworkCapture: Restoring Private DNS mode: {}", previousPrivateDnsMode);
        runQuietly(DeviceManager.rootShellCommand("settings put global private_dns_mode " + previousPrivateDnsMode));
        previousPrivateDnsMode = null;
    }

    private void flushDnsCache() {
        log.info("[*] NetworkCapture: Flushing DNS caches...");

        runQuietly(DeviceManager.rootShellCommand("dumpsys dnsresolver --flush"));
        runQuietly(DeviceManager.rootShellCommand("ndc resolver flushdefaultif"));
        runQuietly(DeviceManager.rootShellCommand("ndc resolver flushnet 0"));

        runQuietly(DeviceManager.rootShellCommand("settings put global airplane_mode_on 1"));
        runQuietly(DeviceManager.rootShellCommand("am broadcast -a android.intent.action.AIRPLANE_MODE --ez state true"));
        try { Thread.sleep(2000); } catch (InterruptedException ignored) {}
        runQuietly(DeviceManager.rootShellCommand("settings put global airplane_mode_on 0"));
        runQuietly(DeviceManager.rootShellCommand("am broadcast -a android.intent.action.AIRPLANE_MODE --ez state false"));

        log.info("[*] NetworkCapture: Waiting 30s for network to reconnect...");
        try { Thread.sleep(30000); } catch (InterruptedException ignored) {}

        waitForConnectivity();

        runQuietly(DeviceManager.rootShellCommand("dumpsys dnsresolver --flush"));

        log.info("[*] NetworkCapture: DNS caches flushed");
    }

    private void waitForConnectivity() {
        log.info("[*] NetworkCapture: Waiting for network connectivity...");
        for (int i = 0; i < 15; i++) {
            try {
                Thread.sleep(1000);
                String output = CommandRunner.run("adb shell ping -c 1 -W 1 8.8.8.8");
                if (output.contains("1 received")) {
                    log.info("[*] NetworkCapture: Network connectivity confirmed");
                    return;
                }
            } catch (Exception e) {
                log.debug("[*] NetworkCapture: Waiting for connectivity... ({}s)", i + 1);
            }
        }
        log.warn("[!] NetworkCapture: Network connectivity not confirmed after 15s — proceeding anyway");
    }

    private void runQuietly(String command) {
        try {
            CommandRunner.run(command);
        } catch (Exception e) {
            log.debug("[*] NetworkCapture: Command skipped: {}", command);
        }
    }
}
