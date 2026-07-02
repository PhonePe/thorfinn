package com.thorfinn.config;

import java.io.IOException;

public class ConfigLoader {
    public static Config loadConfig(String configPath) throws IOException {
        return new ConfigReader().loadConfig(configPath);
    }
}
