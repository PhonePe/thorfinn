package com.thorfinn;

import com.thorfinn.orchestrator.Orchestrator;
import com.thorfinn.utils.VersionInfo;
import com.thorfinn.verification.PocApprovalMode;

public class Main {

    private static final int DEFAULT_TIME_LIMIT = 30000;

    public static void main(String[] args) throws Exception {
        if (args.length < 1 || "-h".equals(args[0]) || "--help".equals(args[0])) {
            printHelp();
            System.exit(args.length < 1 ? 1 : 0);
        }
        if ("-v".equals(args[0]) || "--version".equals(args[0])) {
            System.out.println("Thorfinn " + VersionInfo.getVersion());
            System.exit(0);
        }
        String packageName = args[0];
        int timeLimit = DEFAULT_TIME_LIMIT;
        String configPath = null;
        PocApprovalMode pocMode = PocApprovalMode.INTERACTIVE;

        for (int i = 1; i < args.length; i++) {
            if (("--time-limit".equals(args[i]) || "-t".equals(args[i])) && i + 1 < args.length) {
                try {
                    timeLimit = Integer.parseInt(args[++i]);
                } catch (NumberFormatException e) {
                    System.err.println("Invalid time-limit value: " + args[i] + ". Using default: " + DEFAULT_TIME_LIMIT + "s");
                }
            } else if (("--config".equals(args[i]) || "-c".equals(args[i])) && i + 1 < args.length) {
                configPath = args[++i];
            } else if ("--auto-approve".equals(args[i]) || "-y".equals(args[i])) {
                pocMode = PocApprovalMode.AUTO_APPROVE;
            } else if ("--skip-verify".equals(args[i]) || "-s".equals(args[i])) {
                pocMode = PocApprovalMode.SKIP;
            }
        }

        if (configPath == null || configPath.isBlank()) {
            System.err.println("Error: config not given. Pass the config file with -c/--config <path>.");
            printHelp();
            System.exit(1);
        }

        Orchestrator orchestrator = new Orchestrator();
        orchestrator.execute(packageName, timeLimit, configPath, pocMode);
    }

    private static void printHelp() {
        System.out.println("""
                
                Thorfinn %s - Automated Android Client-Side Security Scanner
                
                Usage:
                  java -jar Thorfinn.jar <package-name> --config <path> [options]
                
                Arguments:
                  <package-name>              Android package name of the target app (must be installed on connected device)
                
                Options:
                  -c, --config <path>         Path to config.yml (required)
                  -t, --time-limit <seconds>  Time limit for CPG/taint analysis (default: 300)
                  -y, --auto-approve          Auto-approve all LLM-generated POC commands without prompting
                  -s, --skip-verify           Skip execution of all LLM-generated POC commands
                  -v, --version               Print the Thorfinn version and exit
                  -h, --help                  Show this help message
                
                Examples:
                  java -jar Thorfinn.jar com.example.app --config /path/to/config.yml
                  java -jar Thorfinn.jar com.example.app -c ./config/config.yml --time-limit 600
                  java -jar Thorfinn.jar com.example.app -c ./config/config.yml --auto-approve
                  java -jar Thorfinn.jar com.example.app -c ./config/config.yml --skip-verify
                """.formatted(VersionInfo.getVersion()));
    }
}
