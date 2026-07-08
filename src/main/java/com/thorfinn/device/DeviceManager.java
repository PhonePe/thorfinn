package com.thorfinn.device;

import com.thorfinn.utils.CommandRunner;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class DeviceManager {

    private static volatile boolean emulatorRoot = false;

    public void checkDeviceConnected() throws Exception {
        log.info("[*] DeviceManager: Checking for connected device...");
        String output = CommandRunner.run("adb devices");
        String[] lines = output.split("\n");
        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("List of")) continue;
            if (line.endsWith("device")) {
                log.info("[*] DeviceManager: Device connected");
                setupRootAccess();
                return;
            }
        }
        throw new RuntimeException("No connected Android device found. Run 'adb devices' to check.");
    }

    private void setupRootAccess() {
        boolean isEmulator = detectEmulator();
        if (!isEmulator) {
            log.info("[*] DeviceManager: Physical device detected - root commands will use 'su -c'");
            return;
        }

        log.info("[*] DeviceManager: Emulator detected - enabling root via 'adb root'");
        try {
            CommandRunner.run("adb root");
            CommandRunner.run("adb wait-for-device");
            Thread.sleep(2000);
            emulatorRoot = true;
            log.info("[*] DeviceManager: Root access enabled - running commands as root via 'adb shell'");
        } catch (Exception e) {
            log.warn("[!] DeviceManager: 'adb root' failed ({}) - falling back to 'su -c'", e.getMessage());
            emulatorRoot = false;
        }
    }

    private boolean detectEmulator() {
        try {
            String qemu = CommandRunner.run("adb shell getprop ro.kernel.qemu").trim();
            if ("1".equals(qemu)) return true;
        } catch (Exception ignored) {
        }
        try {
            String hardware = CommandRunner.run("adb shell getprop ro.hardware").trim().toLowerCase();
            if (hardware.contains("goldfish") || hardware.contains("ranchu")) return true;
        } catch (Exception ignored) {
        }
        try {
            String characteristics = CommandRunner.run("adb shell getprop ro.build.characteristics").trim().toLowerCase();
            if (characteristics.contains("emulator")) return true;
        } catch (Exception ignored) {
        }
        return false;
    }

    public static boolean isEmulatorRoot() {
        return emulatorRoot;
    }

    public static String rootShellCommand(String innerCommand) {
        if (emulatorRoot) {
            return "adb shell '" + innerCommand + "'";
        }
        return "adb shell su -c '" + innerCommand + "'";
    }
}
