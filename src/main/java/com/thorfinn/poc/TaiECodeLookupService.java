package com.thorfinn.poc;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public class TaiECodeLookupService {

    private final Path decompiledRoot;

    public TaiECodeLookupService(String decompiledRootPath) {
        this.decompiledRoot = Paths.get(decompiledRootPath).normalize().toAbsolutePath();
    }

    public String readJavaClassWithFuzzy(String className) throws IOException {
        String fileClassName = className.contains("$")
                ? className.substring(0, className.indexOf('$'))
                : className;

        Path sourcesDir = decompiledRoot.resolve("sources").normalize();
        Path exact = sourcesDir.resolve(fileClassName.replace('.', '/') + ".java").normalize();
        if (exact.startsWith(sourcesDir) && Files.exists(exact)) {
            return Files.readString(exact);
        }

        if (!Files.isDirectory(sourcesDir)) {
            return "Java file not found for: " + className;
        }

        String simpleClassName = fileClassName.substring(fileClassName.lastIndexOf('.') + 1) + ".java";
        List<Path> candidates = new ArrayList<>();
        findFilesByName(sourcesDir, simpleClassName, candidates);

        Path bestMatch = findBestCandidate(candidates, fileClassName, ".java", sourcesDir);
        if (bestMatch != null) {
            return Files.readString(bestMatch);
        }
        return "Java file not found for: " + className;
    }

    public String readSmaliClassWithFuzzy(String className) throws IOException {
        String relativePath = className.replace('.', '/') + ".smali";

        List<Path> smaliDirs;
        try (Stream<Path> stream = Files.list(decompiledRoot)) {
            smaliDirs = stream
                    .filter(Files::isDirectory)
                    .filter(p -> p.getFileName().toString().startsWith("smali"))
                    .toList();
        }

        for (Path smaliDir : smaliDirs) {
            Path exact = smaliDir.resolve(relativePath).normalize();
            if (exact.startsWith(smaliDir) && Files.exists(exact)) {
                return Files.readString(exact);
            }
        }

        String simpleClassName = className.substring(className.lastIndexOf('.') + 1) + ".smali";
        Path bestMatch = null;
        int bestScore = -1;
        String[] originalParts = className.split("\\.");

        for (Path smaliDir : smaliDirs) {
            List<Path> candidates = new ArrayList<>();
            findFilesByName(smaliDir, simpleClassName, candidates);
            for (Path candidate : candidates) {
                String candidateRelative = smaliDir.relativize(candidate).toString();
                String candidatePackage = candidateRelative
                        .replace('/', '.')
                        .replace('\\', '.')
                        .replace(".smali", "");
                int score = scoreMatch(originalParts, candidatePackage.split("\\."));
                if (score > bestScore) {
                    bestScore = score;
                    bestMatch = candidate;
                }
            }
        }

        if (bestMatch != null) {
            return Files.readString(bestMatch);
        }
        return "Smali file not found for: " + className;
    }

    private void findFilesByName(Path rootDir, String fileName, List<Path> results) throws IOException {
        try (Stream<Path> stream = Files.walk(rootDir)) {
            stream.filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().equals(fileName))
                    .forEach(results::add);
        }
    }

    private Path findBestCandidate(List<Path> candidates, String originalClassName, String suffix, Path relativeRoot) {
        String[] originalParts = originalClassName.split("\\.");
        Path bestMatch = null;
        int bestScore = -1;

        for (Path candidate : candidates) {
            String candidateRelative = relativeRoot.relativize(candidate).toString();
            String candidatePackage = candidateRelative
                    .replace('/', '.')
                    .replace('\\', '.')
                    .replace(suffix, "");
            int score = scoreMatch(originalParts, candidatePackage.split("\\."));
            if (score > bestScore) {
                bestScore = score;
                bestMatch = candidate;
            }
        }
        return bestMatch;
    }

    private int scoreMatch(String[] originalParts, String[] candidateParts) {
        int score = 0;
        int minLen = Math.min(originalParts.length, candidateParts.length);
        for (int i = 0; i < minLen; i++) {
            if (originalParts[i].equals(candidateParts[i])) {
                score++;
            }
        }
        return score;
    }
}
