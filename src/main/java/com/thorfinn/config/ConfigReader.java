package com.thorfinn.config;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.yaml.snakeyaml.Yaml;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

public class ConfigReader {

    public Config loadConfig(String configPath) {
        if (configPath == null || configPath.isBlank()) {
            throw new IllegalArgumentException("config not given. Pass the config file with -c/--config <path>.");
        }
        Path resolved = Path.of(configPath).toAbsolutePath();
        try (InputStream input = new FileInputStream(resolved.toFile())) {
            Map<String, Object> config = new Yaml().load(input);
            String json = new GsonBuilder().setPrettyPrinting().create().toJson(config);
            Config result = new Gson().fromJson(json, Config.class);
            loadCvssConfig(result);
            return result;
        } catch (IOException e) {
            throw new RuntimeException("Failed to read config from: " + resolved + ". Check the path passed to --config.", e);
        }
    }

    // cvssConfig lives in its own file; falls back to defaults in FindingSeverityService if absent
    private void loadCvssConfig(Config config) {
        String cvssConfigPath = config.getPathConfigs() == null ? null : config.getPathConfigs().getCvssConfigPath();
        if (cvssConfigPath == null || cvssConfigPath.isBlank()) {
            return;
        }
        Path resolved = Path.of(System.getProperty("user.dir"), cvssConfigPath).toAbsolutePath();
        if (!Files.exists(resolved)) {
            return;
        }
        try (InputStream input = new FileInputStream(resolved.toFile())) {
            Map<String, Object> cvssConfig = new Yaml().load(input);
            String json = new GsonBuilder().setPrettyPrinting().create().toJson(cvssConfig);
            config.setCvssConfig(new Gson().fromJson(json, CvssConfig.class));
        } catch (IOException e) {
            throw new RuntimeException("Failed to read cvss config from: " + resolved, e);
        }
    }
}

