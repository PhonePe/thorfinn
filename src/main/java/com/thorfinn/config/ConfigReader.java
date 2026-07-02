package com.thorfinn.config;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.yaml.snakeyaml.Yaml;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
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
            return new Gson().fromJson(json, Config.class);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read config from: " + resolved + ". Check the path passed to --config.", e);
        }
    }
}
