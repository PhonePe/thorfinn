
### Prerequisites

| Component | Requirement                                   |
|---|-----------------------------------------------|
| OS | macOS or Linux                                |
| RAM | 8 GB minimum, 16 GB recommended for large APKs |
| Java | 17 or higher                                  |
| Maven | 3.6 or higher                                 |
| Python | 3.10+                               |
| Device | Android device or emulator with USB debugging enabled |


### Automated Setup

Thorfinn uses multiple tools for APK extraction, decompilation, analysis, and verification. The setup script installs the required dependencies, prepares the environment, and builds the executable JAR.

```bash
git clone https://github.com/PhonePe/Thorfinn.git --recurse-submodules
cd Thorfinn
./setup.sh
```

After setup completes, the generated fat JAR is available at:

```bash
target/Thorfinn.jar
```

You can run it against any installed Android package just attach a device or emulator and execute:

```bash
java -jar target/Thorfinn.jar <package-name> --config config/config.yml
```

### Build with Changes

After completing the automated setup, you can make code changes and rebuild Thorfinn using Maven:

```bash
mvn clean package -DskipTests
```

Run the updated JAR against any installed Android package after attaching a device or emulator:

```bash
java -jar target/Thorfinn.jar <package-name> --config config/config.yml
```

