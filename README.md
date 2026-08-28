<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue?style=for-the-badge" alt="Platform" />
  <img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License" />
  <img src="https://img.shields.io/badge/AI-Powered-ff6b6b?style=for-the-badge&logo=openai&logoColor=white" alt="AI Powered" />
</p>

<h1 align="center">🔓 APK Security Studio</h1>

<p align="center">
  <strong>AI-Powered Android APK Reverse Engineering & Security Analysis Platform</strong>
</p>

<p align="center">
  A professional-grade toolkit for decompiling, analyzing, patching, and recompiling Android APK files.<br/>
  Features an integrated Web IDE with Monaco Editor, AI-assisted vulnerability analysis,<br/>
  automated security pattern scanning, Smali patch engine, and Frida hook generation.
</p>

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage — Web IDE](#-usage--web-ide)
- [Usage — Desktop GUI](#-usage--desktop-gui)
- [Usage — CLI](#-usage--cli)
- [AI Integration](#-ai-integration)
- [Security Scanner](#-security-scanner)
- [Patch Engine](#-patch-engine)
- [Frida Hook Generator](#-frida-hook-generator)
- [API Reference](#-api-reference)
- [Project Structure](#-project-structure)
- [Configuration](#-configuration)
- [Troubleshooting](#-troubleshooting)
- [Legal Disclaimer](#%EF%B8%8F-legal-disclaimer)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

### 🧠 AI-Powered Analysis
- **Multi-provider support** — Ollama (local), LM Studio (local), Google Gemini (cloud)
- **Intelligent vulnerability detection** — AI identifies security controls and suggests precise Smali modifications
- **Context-aware prompts** — Analyze specific files or the entire APK with custom prompts
- **Auto-model discovery** — Dynamically fetches available models from your local AI server

### 🔍 Security Pattern Scanner
- **Root Detection** — `su` binary, Build.TAGS, Magisk, Xposed, RootBeer library, Busybox
- **License Verification** — License checks, signature verification, In-App Billing, public key validation
- **Emulator Detection** — Build.MODEL, Build.PRODUCT, TelephonyManager IMEI
- **SSL Certificate Pinning** — OkHttp CertificatePinner, custom TrustManager, network security config

### 🩹 Automated Patch Engine
- **20+ built-in patch templates** across 4 security categories
- **Smali-level patching** — Method return override, string replacement, register injection
- **Batch patching** — Apply multiple templates simultaneously
- **Dry-run mode** — Preview diffs before committing changes
- **Revert support** — Automatic `.bak` backups for every patched file

### 🪝 Frida Hook Generator
- **Auto-generated hooks** from scan results
- **Custom hook builder** — Target any class/method with configurable return values
- **Pre-built Frida templates** — SSL pinning bypass, signature spoofing, billing bypass, native root hooks

### 🌐 Web IDE (APK Security Studio)
- **Monaco Editor** — Full VS Code-like code editor with Smali syntax highlighting
- **Real-time console** — WebSocket-powered live output streaming
- **File explorer** — Browse the decompiled APK tree with click-to-edit
- **Build pipeline** — Decode → Scan → Patch → Build → Sign, all from the browser
- **Project management** — Multiple concurrent APK analysis sessions

### 🖥️ Desktop GUI
- **CustomTkinter UI** — Modern dark-themed native application
- **One-click automation** — Full pipeline execution with a single button
- **Configurable patches** — Toggle license bypass, IAP unlock, ad removal independently
- **Integrated file explorer** — Browse and edit decompiled files in-app

---

## 🏗 Architecture

```
┌────────────────────────────────────────────────────────────┐
│                    APK Security Studio                      │
├───────────────┬───────────────┬────────────────────────────┤
│  Web IDE      │  Desktop GUI  │  CLI                       │
│  (Browser)    │  (Tkinter)    │  (Python)                  │
├───────────────┴───────────────┴────────────────────────────┤
│                 Flask + SocketIO Server                     │
│                    (server.py)                              │
├────────────────────────────────────────────────────────────┤
│              APKAnalyzer Core Engine                        │
│         (AI_Revserse_Engineering_APK.py)                    │
├─────────┬──────────┬───────────┬──────────┬───────────────┤
│ Decoder │ Scanner  │ Patcher   │ Builder  │ AI Connector  │
│ apktool │ regex    │ smali     │ apktool  │ ollama/gemini │
│  .jar   │ patterns │ templates │ jarsign  │ lm_studio     │
└─────────┴──────────┴───────────┴──────────┴───────────────┘
```

---

## 📦 Prerequisites

| Tool | Required | Purpose | Install |
|------|----------|---------|---------|
| **Python 3.8+** | ✅ | Runtime | [python.org](https://www.python.org/downloads/) |
| **Java JDK 11+** | ✅ | APKTool, signing | [adoptium.net](https://adoptium.net/) |
| **apktool** | ✅ (included) | Decode/build APKs | Bundled as `apktool_2.12.1.jar` |
| **Ollama / LM Studio** | ⭐ Recommended | Local AI analysis | [ollama.com](https://ollama.com/) |
| **Frida** | ⬜ Optional | Dynamic hooking | `pip install frida-tools` |
| **ADB** | ⬜ Optional | Device deployment | [Android SDK](https://developer.android.com/tools/releases/platform-tools) |

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/ilavarasanAppu/apktool.git
cd apktool
```

### 2. Install Python Dependencies

```bash
pip install flask flask-socketio flask-cors werkzeug requests
```

**Optional dependencies:**

```bash
# For Google Gemini AI support
pip install google-genai

# For Desktop GUI
pip install customtkinter

# For Frida dynamic instrumentation
pip install frida-tools

# For async WebSocket support (recommended)
pip install eventlet
```

### 3. Verify Java Installation

```bash
java -version
# Should output: openjdk version "11.x.x" or higher

keytool -help
# Should display keytool usage information
```

### 4. (Optional) Set Up Local AI

```bash
# Option A: Ollama
ollama pull mistral          # or any model you prefer
ollama serve                 # starts at localhost:11434

# Option B: LM Studio
# Download from https://lmstudio.ai, load a model, start the server
```

---

## ⚡ Quick Start

### Web IDE (Recommended)

```bash
# Windows — double-click or run:
start_web.bat

# Linux / macOS:
python server.py
```

Then open **http://localhost:5000** in your browser.

### Desktop GUI

```bash
# Windows — double-click or run:
start.bat

# Any OS:
python AI_Reverse_Engineering_App.py
```

### CLI (Headless)

```bash
python AI_Revserse_Engineering_APK.py target_app.apk
```

---

## 🌐 Usage — Web IDE

The Web IDE is the primary interface for APK Security Studio, featuring a full-featured browser-based reverse engineering environment.

### Step 1: Upload APK

1. Open **http://localhost:5000** in your browser
2. Click **Upload APK** and select your target `.apk` file (up to 500 MB)
3. Choose your AI provider and model from the sidebar settings

### Step 2: Decode

1. Click **Decode** to decompile the APK using APKTool
2. The file tree populates with the decompiled structure:
   - `AndroidManifest.xml` — App configuration, permissions, components
   - `smali/` — Dalvik bytecode (editable Smali assembly)
   - `res/` — Resources (layouts, strings, drawables)
   - `assets/` — Raw asset files

### Step 3: Security Scan

1. Click **Security Scan** to run the pattern scanner
2. Results are categorized by severity:
   - 🔴 **High** — Root detection, license verification
   - 🟡 **Medium** — Emulator detection, SSL pinning
3. Each finding shows:
   - File path and line number
   - Code snippet
   - Suggested patch template

### Step 4: Apply Patches

1. Review scan findings and select patch templates
2. Use **Dry Run** to preview the diff before applying
3. Apply patches individually or use **Batch Patch** for multiple templates
4. Edit files directly in the Monaco Editor for manual modifications

### Step 5: AI Analysis

1. Click **AI Analyze** to get AI-powered insights
2. Optionally select a specific file for focused analysis
3. Write custom prompts for targeted analysis
4. AI returns:
   - Vulnerability findings
   - Smali patch suggestions
   - Frida hook recommendations

### Step 6: Build & Sign

1. Click **Build** to recompile the modified APK
2. APK is automatically signed with a debug keystore
3. Download the signed APK from the build output panel

---

## 🖥 Usage — Desktop GUI

The Desktop GUI provides a native application experience built with CustomTkinter.

### Sidebar Controls

| Control | Description |
|---------|-------------|
| **AI Provider** | Select Ollama, LM Studio, or Gemini |
| **AI Model** | Detected models from your AI server |
| **API Key / URL** | API key (Gemini) or custom endpoint URL |
| **Refresh Models** | Re-fetch available models |

### Action Buttons

| Button | Description |
|--------|-------------|
| **AUTO COMPLETE** | Runs the full pipeline: Decode → Analyze → Patch → Build → Sign |
| **1. Decode APK** | Decompile the APK with APKTool |
| **2. AI Analysis & Patch** | Run AI analysis and apply automated patches |
| **3. Build APK** | Recompile modified Smali back to APK |
| **4. Sign APK** | Sign the built APK with a debug keystore |

### Tabs

- **Optimization Prompt** — Custom instructions for the AI analysis
- **Automation Settings** — Toggle auto-patches (license bypass, IAP unlock, ad removal)
- **File Explorer** — Browse and edit decompiled files

---

## 💻 Usage — CLI

Run a fully automated analysis pipeline from the command line:

```bash
python AI_Revserse_Engineering_APK.py <path-to-apk>
```

This executes:
1. APK decoding with APKTool
2. Manifest extraction and parsing
3. String resource extraction
4. Smali file analysis
5. Automated offline patching (license, IAP, ads)
6. AI-powered analysis
7. APK recompilation and signing

Output is saved to `./apk_analysis_output/<apk_name>/`.

---

## 🤖 AI Integration

APK Security Studio supports three AI providers for intelligent code analysis:

### Ollama (Local — Recommended)

```bash
# Install and run Ollama
ollama pull mistral        # lightweight, fast
ollama pull codellama      # better for code analysis
ollama pull deepseek-coder # excellent for reverse engineering
ollama serve
```

- **Default endpoint:** `http://localhost:11434`
- **No API key required**
- **Fully offline** — no data leaves your machine

### LM Studio (Local)

1. Download from [lmstudio.ai](https://lmstudio.ai)
2. Load a model (e.g., CodeLlama, Mistral, DeepSeek)
3. Start the local server (default: `http://localhost:1234`)

### Google Gemini (Cloud)

1. Get an API key from [Google AI Studio](https://aistudio.google.com/apikey)
2. Install the SDK: `pip install google-genai`
3. Enter your API key in the settings panel
4. Available models: `gemini-2.0-flash`, `gemini-1.5-pro`, `gemini-1.5-flash`

---

## 🔍 Security Scanner

The scanner uses regex pattern matching across all decompiled Smali and XML files to detect security controls.

### Detection Categories

#### Root Detection (`root_detection`)
| Pattern ID | What It Detects |
|-----------|-----------------|
| `su_binary` | Checks for `/system/bin/su`, `/sbin/su`, etc. |
| `build_tags` | `Build.TAGS` comparison against `test-keys` |
| `build_fingerprint` | `Build.FINGERPRINT` checks for `generic`/`unknown` |
| `superuser_pkg` | Superuser app package detection (SuperSU, etc.) |
| `rootbeer` | RootBeer library usage |
| `busybox` | Busybox binary detection |
| `xposed` | Xposed framework detection |
| `magisk` | Magisk detection |

#### License Verification (`license_verification`)
| Pattern ID | What It Detects |
|-----------|-----------------|
| `check_license` | `checkLicense`, `verifyLicense`, `isLicensed` methods |
| `signature_check` | `PackageInfo.GET_SIGNATURES` verification |
| `base64_pubkey` | Base64-encoded RSA public keys for license validation |
| `in_app_billing` | `IInAppBillingService` and billing client APIs |
| `license_validator` | Google Play licensing library classes |
| `billing_client` | `BillingClient` API usage |

#### Emulator Detection (`emulator_detection`)
| Pattern ID | What It Detects |
|-----------|-----------------|
| `build_model` | `Build.MODEL` checks for emulator strings |
| `build_product` | `Build.PRODUCT` checks for `sdk`/`emulator` |
| `telephony_imei` | `getDeviceId`/`getImei` for null/zero checks |

#### SSL Pinning (`ssl_pinning`)
| Pattern ID | What It Detects |
|-----------|-----------------|
| `cert_pinner` | OkHttp `CertificatePinner` |
| `trust_manager` | Custom `X509TrustManager` implementations |
| `net_security` | `network-security-config` XML references |

---

## 🩹 Patch Engine

### Patch Strategies

| Strategy | Description | Use Case |
|----------|-------------|----------|
| `force_method_return_true` | Replaces method body to return `1` (true) | License checks, premium flags |
| `force_method_return_false` | Replaces method body to return `0` (false) | Root detection, emulator checks |
| `force_method_return_void` | Replaces method body with `return-void` | Ad loading, analytics calls |
| `smali_replace` | Find-and-replace specific Smali instructions | Build property spoofing |
| `frida_hook` | Generates Frida script instead of static patch | Signature checks, billing, SSL |

### Example: Apply a Patch via API

```bash
# Dry run — preview changes
curl -X POST http://localhost:5000/api/<project_id>/patch \
  -H "Content-Type: application/json" \
  -d '{"template_id": "license_check_true", "dry_run": true}'

# Apply for real
curl -X POST http://localhost:5000/api/<project_id>/patch \
  -H "Content-Type: application/json" \
  -d '{"template_id": "license_check_true"}'

# Batch apply multiple patches
curl -X POST http://localhost:5000/api/<project_id>/patch/batch \
  -H "Content-Type: application/json" \
  -d '{"template_ids": ["license_check_true", "ad_removal", "su_binary_check_bypass"]}'
```

---

## 🪝 Frida Hook Generator

Generate dynamic instrumentation scripts for runtime analysis:

### Custom Hook

```bash
curl -X POST http://localhost:5000/api/<project_id>/frida/hook \
  -H "Content-Type: application/json" \
  -d '{
    "class_name": "com.example.app.LicenseManager",
    "method_name": "isLicensed",
    "return_value": "true"
  }'
```

### Auto-Generate from Scan Results

```bash
curl -X POST http://localhost:5000/api/<project_id>/frida/from-scan
```

### Pre-Built Frida Templates

| Template | Target |
|----------|--------|
| `native_root_hook` | JNI native root detection methods |
| `signature_spoof_hook` | `PackageManager.getPackageInfo` signature verification |
| `billing_bypass_hook` | Google Play Billing Client |
| `telephony_spoof_hook` | `TelephonyManager.getDeviceId` / `getLine1Number` |
| `ssl_pinning_hook` | OkHttp `CertificatePinner` + custom `TrustManager` |

---

## 📡 API Reference

The Web IDE backend exposes a REST + WebSocket API.

### Health & System

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | System health check, tool availability |
| `GET` | `/api/ai/models?provider=ollama` | List available AI models |
| `GET` | `/api/patch-templates` | Get all patch template definitions |

### Project Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/upload` | Upload APK (multipart form data) |
| `GET` | `/api/projects` | List all active projects |
| `DELETE` | `/api/projects/<id>` | Delete a project |

### Analysis Pipeline

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/<id>/decode` | Decode APK with APKTool |
| `GET` | `/api/<id>/tree` | Get decompiled file tree |
| `GET` | `/api/<id>/file?path=<rel>` | Read a file |
| `PUT` | `/api/<id>/file` | Write/save a file |
| `POST` | `/api/<id>/file/revert` | Revert to `.bak` backup |
| `POST` | `/api/<id>/scan` | Run security pattern scan |
| `GET` | `/api/<id>/scan/results` | Get scan results |
| `POST` | `/api/<id>/ai/analyze` | Run AI analysis |
| `GET` | `/api/<id>/manifest` | Get parsed manifest |
| `GET` | `/api/<id>/analysis` | Get full analysis results |

### Patching & Building

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/<id>/patch` | Apply a patch template |
| `POST` | `/api/<id>/patch/batch` | Apply multiple patches |
| `GET` | `/api/<id>/patch/history` | Get patch history |
| `POST` | `/api/<id>/frida/hook` | Generate custom Frida hook |
| `POST` | `/api/<id>/frida/from-scan` | Generate Frida script from scan |
| `POST` | `/api/<id>/build` | Build modified APK |
| `GET` | `/api/<id>/download/<file>` | Download built APK |

### WebSocket Events

| Event | Direction | Description |
|-------|-----------|-------------|
| `connected` | Server → Client | Connection confirmation |
| `console_log` | Server → Client | Real-time log messages |
| `decode_complete` | Server → Client | Decode operation finished |
| `scan_complete` | Server → Client | Security scan finished |
| `build_complete` | Server → Client | Build pipeline finished |
| `ai_response` | Server → Client | AI analysis result |

---

## 📁 Project Structure

```
apktool/
├── AI_Revserse_Engineering_APK.py  # Core engine — APKAnalyzer class
├── AI_Reverse_Engineering_App.py   # Desktop GUI (CustomTkinter)
├── server.py                       # Flask + SocketIO web server
├── patch_templates.json            # 20+ security patch definitions
├── apktool_2.12.1.jar              # Bundled APKTool
├── start.bat                       # Launch desktop GUI (Windows)
├── start_web.bat                   # Launch web server (Windows)
├── web/                            # Web IDE frontend
│   ├── index.html                  # Main HTML — IDE layout
│   ├── style.css                   # Full CSS theme & components
│   ├── app.js                      # Frontend application logic
│   ├── api.js                      # API client module
│   └── monaco-setup.js             # Monaco Editor configuration
└── apk_analysis_output/            # Analysis output directory
    ├── uploads/                    # Uploaded APK files
    └── projects/                   # Per-project decoded & patched files
```

---

## ⚙ Configuration

### Server Settings

| Setting | Default | Environment |
|---------|---------|-------------|
| Host | `0.0.0.0` | All interfaces |
| Port | `5000` | `http://localhost:5000` |
| Max Upload | `500 MB` | `app.config['MAX_CONTENT_LENGTH']` |

### AI Provider Defaults

| Provider | Default URL | Auth |
|----------|------------|------|
| Ollama | `http://localhost:11434` | None |
| LM Studio | `http://localhost:1234` | None |
| Gemini | Google Cloud | API Key required |

---

## 🔧 Troubleshooting

### Common Issues

<details>
<summary><strong>❌ "apktool jar not found"</strong></summary>

Ensure `apktool_2.12.1.jar` is in the project root directory. The engine searches for:
1. `./apktool_2.12.1.jar`
2. `./apktool.jar`

</details>

<details>
<summary><strong>❌ "Java not found in PATH"</strong></summary>

Install Java JDK 11+ and ensure `java`, `keytool`, and `jarsigner` are in your system PATH:
```bash
java -version
keytool -help
jarsigner -help
```
</details>

<details>
<summary><strong>❌ AI returns no response</strong></summary>

- **Ollama:** Verify it's running with `curl http://localhost:11434/api/tags`
- **LM Studio:** Ensure a model is loaded and the server is started
- **Gemini:** Check your API key is valid and `google-genai` is installed

</details>

<details>
<summary><strong>❌ Build fails after patching</strong></summary>

- Verify Smali syntax is valid (register count, instruction format)
- Use **Revert** to restore original files from `.bak` backups
- Check the console log for specific APKTool error messages

</details>

<details>
<summary><strong>❌ WebSocket connection drops</strong></summary>

- Install `eventlet` for improved async support: `pip install eventlet`
- Check that no firewall is blocking port 5000
- Try refreshing the browser page

</details>

---

## ⚖️ Legal Disclaimer

> **⚠️ FOR EDUCATIONAL AND AUTHORIZED SECURITY RESEARCH ONLY**
>
> This tool is designed for:
> - **Security researchers** conducting authorized penetration testing
> - **Developers** analyzing their own applications
> - **Students** learning about Android security and reverse engineering
> - **Bug bounty hunters** with explicit authorization
>
> **You are solely responsible for ensuring you have proper authorization before analyzing any APK.**
> Unauthorized reverse engineering, modification, or distribution of applications may violate:
> - Software license agreements
> - The Computer Fraud and Abuse Act (CFAA)
> - The Digital Millennium Copyright Act (DMCA)
> - Local computer crime laws in your jurisdiction
>
> The authors and contributors of this project assume **no liability** for misuse.

---

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

1. **Fork** the repository
2. **Create a branch**: `git checkout -b feature/my-feature`
3. **Commit changes**: `git commit -m "feat: add new feature"`
4. **Push**: `git push origin feature/my-feature`
5. **Open a Pull Request**

### Areas for Contribution

- Additional patch templates for new security patterns
- Support for more AI providers (Anthropic, OpenAI, etc.)
- Jadx integration for Java decompilation
- Linux/macOS launch scripts
- Unit tests and CI/CD pipeline
- Documentation and tutorials

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <strong>Built with ❤️ for the Android security research community</strong>
</p>

<p align="center">
  <a href="https://github.com/ilavarasanAppu/apktool">⭐ Star this repo</a> •
  <a href="https://github.com/ilavarasanAppu/apktool/issues">🐛 Report Bug</a> •
  <a href="https://github.com/ilavarasanAppu/apktool/issues">💡 Request Feature</a>
</p>
