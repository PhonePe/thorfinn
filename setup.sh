#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

THORFINN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }

command_exists() { command -v "$1" &>/dev/null; }

detect_os() {
    case "$(uname -s)" in
        Darwin*) OS="macos" ;;
        Linux*)  OS="linux" ;;
        *)       error "Unsupported OS: $(uname -s). Only macOS and Linux are supported." ;;
    esac
    info "Detected OS: $OS"
}

ensure_package_manager() {
    if [[ "$OS" == "macos" ]]; then
        if ! command_exists brew; then
            info "Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
    elif [[ "$OS" == "linux" ]]; then
        if ! command_exists apt-get; then
            error "This script requires apt-get (Debian/Ubuntu). For other distros, install dependencies manually."
        fi
        sudo apt-get update -qq
    fi
}

install_pkg() {
    local name="$1"
    local brew_name="${2:-$1}"
    local apt_name="${3:-$1}"

    if command_exists "$name"; then
        success "$name is already installed"
        return
    fi

    info "Installing $name..."
    if [[ "$OS" == "macos" ]]; then
        brew install "$brew_name"
    else
        sudo apt-get install -y "$apt_name"
    fi
    success "$name installed"
}

ensure_java() {
    if command_exists java && java -version >/dev/null 2>&1; then
        JAVA_VER=$(java -version 2>&1 | head -1 | awk -F '"' '{print $2}' | cut -d. -f1)
        if [[ "$JAVA_VER" =~ ^[0-9]+$ ]] && [[ "$JAVA_VER" -ge 17 ]]; then
            success "Java $JAVA_VER is already installed"
            return
        fi
        warn "Java ${JAVA_VER:-unknown} found, but Java 17+ is required"
    else
        warn "No working Java runtime found"
    fi

    info "Installing Java 17 (Temurin)..."
    if [[ "$OS" == "macos" ]]; then
        brew install --cask temurin@17
    else
        sudo apt-get install -y temurin-17-jdk 2>/dev/null || {
            sudo apt-get install -y wget apt-transport-https
            wget -qO - https://packages.adoptium.net/artifactory/api/gpg/key/public | sudo tee /etc/apt/trusted.gpg.d/adoptium.asc
            echo "deb https://packages.adoptium.net/artifactory/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/adoptium.list
            sudo apt-get update -qq
            sudo apt-get install -y temurin-17-jdk
        }
    fi

    if ! java -version >/dev/null 2>&1; then
        error "Java 17 was installed but no working 'java' runtime is on PATH. Open a new terminal (or set JAVA_HOME) and re-run ./setup.sh"
    fi
    success "Java 17 installed"
}

ensure_maven() {
    if command_exists mvn; then
        success "Maven is already installed ($(mvn --version | head -1))"
        return
    fi
    install_pkg mvn maven maven
}

ensure_python() {
    if command_exists python3 && python3 --version >/dev/null 2>&1; then
        success "Python3 is already installed ($(python3 --version 2>&1))"
    else
        warn "No working Python3 runtime found"
        install_pkg python3 python3 python3
    fi

    if ! command_exists pip3 || ! pip3 --version >/dev/null 2>&1; then
        info "Installing pip3..."
        if [[ "$OS" == "linux" ]]; then
            sudo apt-get install -y python3-pip
        elif [[ "$OS" == "macos" ]]; then
            python3 -m ensurepip --upgrade 2>/dev/null || true
        fi
    fi
}

ensure_adb() {
    if command_exists adb; then
        success "ADB is already installed ($(adb --version | head -1))"
        return
    fi
    info "Installing Android platform-tools (ADB)..."
    if [[ "$OS" == "macos" ]]; then
        brew install --cask android-platform-tools
    else
        sudo apt-get install -y android-tools-adb
    fi
    success "ADB installed"
}

ensure_jadx() {
    if command_exists jadx; then
        success "JADX is already installed"
        return
    fi
    info "Installing JADX..."
    if [[ "$OS" == "macos" ]]; then
        brew install jadx
    else
        JADX_VERSION="1.5.0"
        wget -q "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -O /tmp/jadx.zip
        sudo unzip -qo /tmp/jadx.zip -d /opt/jadx
        sudo ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx
        rm -f /tmp/jadx.zip
    fi
    success "JADX installed"
}

ensure_semgrep() {
    if command_exists semgrep; then
        success "Semgrep is already installed ($(semgrep --version))"
        return
    fi
    info "Installing Semgrep..."
    pip3 install semgrep
    success "Semgrep installed"
}

ensure_trufflehog() {
    if command_exists trufflehog; then
        success "TruffleHog is already installed"
        return
    fi
    info "Installing TruffleHog..."
    if [[ "$OS" == "macos" ]]; then
        brew install trufflehog
    else
        curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin
    fi
    success "TruffleHog installed"
}

ensure_apktool() {
    if command_exists apktool; then
        success "APKTool is already installed"
        return
    fi
    info "Installing APKTool..."
    if [[ "$OS" == "macos" ]]; then
        brew install apktool
    else
        sudo apt-get install -y apktool
    fi
    success "APKTool installed"
}

setup_config() {
    local config_file="$THORFINN_DIR/config/config.yml"
    local template_file="$THORFINN_DIR/config/config.template.yml"

    if [[ -f "$config_file" ]]; then
        success "config/config.yml already exists"
        return
    fi

    if [[ -f "$template_file" ]]; then
        info "Creating config/config.yml from template..."
        cp "$template_file" "$config_file"
        warn "Config created at: $config_file"
        warn "Please edit config/config.yml to set your LLM API key and base URL"
    else
        error "Template config not found at: $template_file"
    fi
}

setup_directories() {
    info "Creating required directories..."
    mkdir -p "$THORFINN_DIR/resources/apk"
    mkdir -p "$THORFINN_DIR/resources/decompiled_apks"
    mkdir -p "$THORFINN_DIR/resources/taie_output"
    mkdir -p "$THORFINN_DIR/resources/output"
    success "Directories ready"
}

build_jar() {
    info "Building Thorfinn JAR..."
    cd "$THORFINN_DIR"
    mvn clean package -q -DskipTests
    if [[ -f "$THORFINN_DIR/target/Thorfinn.jar" ]]; then
        success "Build successful! JAR at: target/Thorfinn.jar"
    else
        error "Build failed - Thorfinn.jar not found in target/"
    fi
}

print_summary() {
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  Thorfinn setup complete!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "  Usage:"
    echo "    java -jar target/Thorfinn.jar <package-name> --config <path> [options]"
    echo ""
    echo "  Example:"
    echo "    java -jar target/Thorfinn.jar com.example.app --config config/config.yml --time-limit 600"
    echo ""
    echo "  Prerequisites before running:"
    echo "    1. Connect an Android device with USB debugging enabled"
    echo "    2. Ensure the target app is installed on the device"
    echo "    3. Edit config/config.yml with your LLM API key (pass it via --config)"
    echo ""
}

main() {
    echo ""
    echo -e "${CYAN}⚔️  Thorfinn - Setup & Build${NC}"
    echo ""

    detect_os
    ensure_package_manager

    info "Installing dependencies..."
    echo ""

    ensure_java
    ensure_maven
    ensure_python
    ensure_adb
    ensure_jadx
    ensure_semgrep
    ensure_trufflehog
    ensure_apktool

    echo ""
    setup_directories
    setup_config
    echo ""
    build_jar
    print_summary
}

main "$@"

