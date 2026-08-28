import subprocess
import os
import json
import shutil
import requests
import re
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List, Callable, Tuple

try:
    from google import genai
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ─── Security Pattern Database ────────────────────────────────────────────────

SECURITY_PATTERNS = {
    "root_detection": {
        "label": "Root Detection",
        "severity": "high",
        "color": "#ff4757",
        "patterns": [
            {"id": "su_binary",         "label": "su Binary Check",         "regex": r"/system/bin/su|/sbin/su|/system/xbin/su|/su/bin/su",              "type": "string_const"},
            {"id": "build_tags",        "label": "Build.TAGS Check",         "regex": r"android/os/Build;->TAGS",                                          "type": "smali_field"},
            {"id": "build_fingerprint", "label": "Build.FINGERPRINT Check",  "regex": r"android/os/Build;->FINGERPRINT",                                    "type": "smali_field"},
            {"id": "superuser_pkg",     "label": "Superuser Package Check",  "regex": r"com\.noshufou\.android\.su|eu\.chainfire\.supersu|com\.koushikdutta\.superuser", "type": "string_const"},
            {"id": "rootbeer",          "label": "RootBeer Library",         "regex": r"Lcom/scottyab/rootbeer/RootBeer;",                                   "type": "smali_class"},
            {"id": "busybox",           "label": "Busybox Detection",        "regex": r"busybox",                                                            "type": "string_const"},
            {"id": "xposed",            "label": "Xposed Framework Check",   "regex": r"de\.robv\.android\.xposed|XposedBridge",                             "type": "string_const"},
            {"id": "magisk",            "label": "Magisk Detection",         "regex": r"magisk|MAGISK",                                                      "type": "string_const"},
        ]
    },
    "license_verification": {
        "label": "License Verification",
        "severity": "high",
        "color": "#ffa502",
        "patterns": [
            {"id": "check_license",     "label": "checkLicense Method",      "regex": r"checkLicense|verifyLicense|isLicensed|hasLicense|isFullVersion",      "type": "method_name"},
            {"id": "signature_check",   "label": "Signature Verification",   "regex": r"getPackageInfo.*GET_SIGNATURES|checkSignature|verifySignature",        "type": "smali_invoke"},
            {"id": "base64_pubkey",     "label": "Base64 License Key",       "regex": r"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ",                                     "type": "string_const"},
            {"id": "in_app_billing",    "label": "In-App Billing Service",   "regex": r"IInAppBillingService|com\.android\.vending\.billing",                 "type": "string_const"},
            {"id": "license_validator", "label": "LicenseValidator Class",   "regex": r"LicenseValidator|com/google/android/vending/licensing",                "type": "smali_class"},
            {"id": "billing_client",    "label": "BillingClient API",        "regex": r"com/android/billingclient/api/BillingClient",                          "type": "smali_class"},
        ]
    },
    "emulator_detection": {
        "label": "Emulator Detection",
        "severity": "medium",
        "color": "#2ed573",
        "patterns": [
            {"id": "build_model",       "label": "Build.MODEL Emulator Check","regex": r"android/os/Build;->MODEL",                                           "type": "smali_field"},
            {"id": "build_product",     "label": "Build.PRODUCT Emulator",   "regex": r"android/os/Build;->PRODUCT",                                          "type": "smali_field"},
            {"id": "telephony_imei",    "label": "TelephonyManager IMEI",    "regex": r"getDeviceId|getImei",                                                  "type": "method_name"},
        ]
    },
    "ssl_pinning": {
        "label": "SSL Certificate Pinning",
        "severity": "medium",
        "color": "#5352ed",
        "patterns": [
            {"id": "cert_pinner",       "label": "OkHttp CertificatePinner", "regex": r"okhttp3/CertificatePinner",                                            "type": "smali_class"},
            {"id": "trust_manager",     "label": "Custom TrustManager",      "regex": r"checkServerTrusted|X509TrustManager",                                  "type": "method_name"},
            {"id": "net_security",      "label": "Network Security Config",  "regex": r"network-security-config|networkSecurityConfig",                         "type": "string_const"},
        ]
    }
}


class APKAnalyzer:
    """
    Professional APK Analyzer and Reverse Engineering Tool with AI integration.
    Extended for APK Security Studio web platform.
    """
    def __init__(
        self,
        apk_path: str,
        output_dir: str = "./apk_output",
        ai_provider: str = "ollama",
        ai_model: str = "mistral",
        api_key: str = "",
        custom_url: str = "",
        log_callback: Optional[Callable[[str], None]] = None
    ):
        self.apk_path = Path(apk_path)
        self.output_dir = Path(output_dir)
        self.extracted_dir = self.output_dir / "extracted"
        self.ai_provider = ai_provider.lower().replace(" ", "_")
        self.ai_model = ai_model
        self.api_key = api_key
        self.custom_url = custom_url
        self.log_callback = log_callback
        self.analysis_results = {}
        self._patch_history: List[Dict] = []

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.extracted_dir.mkdir(parents=True, exist_ok=True)

        # Load patch templates
        templates_path = Path(__file__).parent / "patch_templates.json"
        if templates_path.exists():
            with open(templates_path, "r", encoding="utf-8") as f:
                self.patch_templates = json.load(f)
        else:
            self.patch_templates = {}

    def log(self, message: str, level: str = "info"):
        """Centralized logging with callback support."""
        if self.log_callback:
            self.log_callback(message)
        if level == "info":
            logger.info(message)
        elif level == "error":
            logger.error(message)
        elif level == "warning":
            logger.warning(message)

    def _run_command(self, cmd: List[str], timeout: int = 300, cwd: str = None) -> Optional[subprocess.CompletedProcess]:
        """Helper to run shell commands safely."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                cwd=cwd or str(Path(__file__).parent)
            )
            return result
        except Exception as e:
            self.log(f"Command failed: {' '.join(map(str, cmd))}. Error: {e}", "error")
            return None

    def _run_command_stream(self, cmd: List[str], cwd: str = None):
        """Generator that yields lines from a subprocess in real-time."""
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=cwd or str(Path(__file__).parent)
            )
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    self.log(line)
                    yield line
            proc.wait()
            yield f"__EXIT__{proc.returncode}"
        except Exception as e:
            yield f"__ERROR__{e}"

    # ─── Core Decompilation ──────────────────────────────────────────────────

    def decode_apk(self) -> bool:
        """Decode APK using APKTool."""
        self.log(f"[*] Decoding APK: {self.apk_path.name}")

        jar_candidates = [
            Path(__file__).parent / "apktool_2.12.1.jar",
            Path(__file__).parent / "apktool.jar",
            Path("apktool_2.12.1.jar"),
            Path("apktool.jar"),
        ]
        jar_path = next((str(j) for j in jar_candidates if j.exists()), None)
        if not jar_path:
            self.log("[-] apktool jar not found!", "error")
            return False

        cmd = ["java", "-jar", jar_path, "decode", str(self.apk_path), "-o", str(self.extracted_dir), "-f"]
        result = self._run_command(cmd)
        if result and result.returncode == 0:
            self.log("[+] APK decoded successfully.")
            return True

        error_msg = result.stderr if result else "Unknown error"
        self.log(f"[-] Decoding failed: {error_msg}", "error")
        return False

    def decode_apk_stream(self):
        """Stream decode output line by line."""
        jar_candidates = [
            Path(__file__).parent / "apktool_2.12.1.jar",
            Path(__file__).parent / "apktool.jar",
        ]
        jar_path = next((str(j) for j in jar_candidates if j.exists()), None)
        if not jar_path:
            yield "__ERROR__apktool jar not found"
            return
        cmd = ["java", "-jar", jar_path, "decode", str(self.apk_path), "-o", str(self.extracted_dir), "-f"]
        yield from self._run_command_stream(cmd)

    # ─── Manifest Extraction ─────────────────────────────────────────────────

    def extract_manifest(self) -> Optional[Dict[str, Any]]:
        """Extract and parse AndroidManifest.xml."""
        self.log("[*] Extracting AndroidManifest.xml...")
        manifest_path = self.extracted_dir / "AndroidManifest.xml"

        if not manifest_path.exists():
            self.log("[-] AndroidManifest.xml not found.", "error")
            return None

        try:
            content = manifest_path.read_text(encoding='utf-8', errors='ignore')
            package = re.search(r'package="([^"]+)"', content)
            version = re.search(r'versionName="([^"]+)"', content)
            version_code = re.search(r'versionCode="([^"]+)"', content)
            min_sdk = re.search(r'android:minSdkVersion="([^"]+)"', content)
            target_sdk = re.search(r'android:targetSdkVersion="([^"]+)"', content)

            # Security flags
            debuggable = 'android:debuggable="true"' in content
            allow_backup = 'android:allowBackup="true"' in content
            cleartext = 'android:usesCleartextTraffic="true"' in content
            network_sec = 'network-security-config' in content

            permissions = re.findall(r'uses-permission android:name="([^"]+)"', content)
            activities = re.findall(r'<activity[^>]+android:name="([^"]+)"', content)

            manifest_info = {
                "package": package.group(1) if package else "Unknown",
                "version": version.group(1) if version else "Unknown",
                "version_code": version_code.group(1) if version_code else "Unknown",
                "min_sdk": min_sdk.group(1) if min_sdk else "Unknown",
                "target_sdk": target_sdk.group(1) if target_sdk else "Unknown",
                "debuggable": debuggable,
                "allow_backup": allow_backup,
                "cleartext_traffic": cleartext,
                "network_security_config": network_sec,
                "permissions": permissions,
                "activities": activities,
                "raw_content": content[:5000]
            }

            self.analysis_results['manifest'] = manifest_info
            self.log(f"[+] Package: {manifest_info['package']} (v{manifest_info['version']})")
            return manifest_info
        except Exception as e:
            self.log(f"[-] Manifest extraction error: {e}", "error")
            return None

    # ─── Security Pattern Scanner ─────────────────────────────────────────────

    def scan_security_patterns(self) -> Dict[str, Any]:
        """
        Scan all decompiled smali files for known security control patterns.
        Returns a structured findings report with file + line references.
        """
        self.log("[*] Scanning for security patterns...")
        findings: Dict[str, List[Dict]] = {}
        total = 0

        smali_files = list(self.extracted_dir.glob("**/*.smali"))
        xml_files = list(self.extracted_dir.glob("**/*.xml"))
        all_files = smali_files + xml_files

        self.log(f"[*] Scanning {len(smali_files)} smali + {len(xml_files)} xml files...")

        for category_id, category in SECURITY_PATTERNS.items():
            findings[category_id] = []
            for pattern in category["patterns"]:
                regex = re.compile(pattern["regex"], re.IGNORECASE)

                for file_path in all_files:
                    try:
                        content = file_path.read_text(encoding='utf-8', errors='ignore')
                        for line_num, line in enumerate(content.splitlines(), 1):
                            if regex.search(line):
                                rel_path = str(file_path.relative_to(self.extracted_dir)).replace("\\", "/")
                                findings[category_id].append({
                                    "pattern_id": pattern["id"],
                                    "pattern_label": pattern["label"],
                                    "file": rel_path,
                                    "line": line_num,
                                    "snippet": line.strip()[:200],
                                    "type": pattern["type"],
                                    "severity": category["severity"],
                                    "category_label": category["label"],
                                    "suggested_template": self._suggest_template(pattern["id"])
                                })
                                total += 1
                    except Exception:
                        continue

        self.log(f"[+] Security scan complete. Found {total} potential issues.")
        self.analysis_results["security_scan"] = findings
        return findings

    def _suggest_template(self, pattern_id: str) -> Optional[str]:
        """Map a detected pattern to the best patch template."""
        mapping = {
            "su_binary":        "su_binary_check_bypass",
            "build_tags":       "build_tags_bypass",
            "build_fingerprint":"build_fingerprint_bypass",
            "superuser_pkg":    "superuser_apk_bypass",
            "rootbeer":         "rootbeer_bypass",
            "busybox":          "busybox_bypass",
            "xposed":           "xposed_bypass",
            "magisk":           "xposed_bypass",
            "check_license":    "license_check_true",
            "signature_check":  "signature_verify_bypass",
            "base64_pubkey":    "base64_pubkey_nullify",
            "in_app_billing":   "in_app_billing_bypass",
            "license_validator":"license_check_true",
            "billing_client":   "in_app_billing_bypass",
            "build_model":      "build_model_bypass",
            "build_product":    "build_product_bypass",
            "telephony_imei":   "telephony_imei_bypass",
            "cert_pinner":      "ssl_pinning_universal",
            "trust_manager":    "ssl_pinning_universal",
            "net_security":     "ssl_pinning_universal",
        }
        return mapping.get(pattern_id)

    # ─── Smali File Tree ─────────────────────────────────────────────────────

    def get_file_tree(self, root: Optional[str] = None) -> Dict:
        """Return recursive file tree as JSON-serializable dict."""
        base = Path(root) if root else self.extracted_dir
        if not base.exists():
            return {"error": "Path not found"}

        def _build(path: Path) -> Dict:
            node = {
                "name": path.name,
                "path": str(path).replace("\\", "/"),
                "rel": str(path.relative_to(self.extracted_dir)).replace("\\", "/") if path != self.extracted_dir else "",
                "is_dir": path.is_dir(),
                "children": []
            }
            if path.is_dir():
                try:
                    items = sorted(path.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
                    node["children"] = [_build(child) for child in items]
                except PermissionError:
                    pass
            else:
                node["size"] = path.stat().st_size
                node["ext"] = path.suffix.lower()
            return node

        return _build(base)

    def read_file(self, rel_path: str) -> Dict[str, Any]:
        """Read a file from the extracted APK and return its content."""
        full_path = self.extracted_dir / rel_path
        if not full_path.exists():
            return {"error": "File not found"}
        try:
            content = full_path.read_text(encoding='utf-8', errors='ignore')
            return {
                "path": rel_path,
                "content": content,
                "size": full_path.stat().st_size,
                "ext": full_path.suffix.lower()
            }
        except Exception as e:
            return {"error": str(e)}

    def write_file(self, rel_path: str, content: str) -> Dict[str, Any]:
        """Write modified content back to a file. Keeps backup."""
        full_path = self.extracted_dir / rel_path
        if not full_path.exists():
            return {"error": "File not found"}
        try:
            backup_path = full_path.with_suffix(full_path.suffix + ".bak")
            if not backup_path.exists():
                shutil.copy2(full_path, backup_path)
            full_path.write_text(content, encoding='utf-8')
            return {"success": True, "path": rel_path}
        except Exception as e:
            return {"error": str(e)}

    # ─── Patch Engine ─────────────────────────────────────────────────────────

    def apply_patch_template(
        self,
        template_id: str,
        target_file: Optional[str] = None,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Apply a named patch template. If target_file is given, apply only there;
        otherwise scan all smali files. dry_run returns diff without writing.
        """
        # Find template in all categories
        template = None
        for cat in self.patch_templates.get("categories", {}).values():
            if template_id in cat.get("templates", {}):
                template = cat["templates"][template_id]
                break

        if not template:
            return {"error": f"Template '{template_id}' not found"}

        strategy = template.get("patch_strategy", "")
        target_pattern = re.compile(template.get("target_pattern", ""), re.IGNORECASE)
        results = []

        if strategy in ("force_method_return_true", "force_method_return_false", "force_method_return_void"):
            files = [self.extracted_dir / target_file] if target_file else list(self.extracted_dir.glob("**/*.smali"))
            replacement = template.get("replacement_smali_bool") or template.get("replacement_smali") or ""
            if strategy == "force_method_return_void":
                replacement = template.get("replacement_smali", ".registers 1\n    return-void")

            for fp in files:
                if not fp.exists():
                    continue
                try:
                    original = fp.read_text(encoding='utf-8', errors='ignore')
                    patched = self._patch_smali_methods(original, target_pattern, replacement)
                    if patched != original:
                        diff = self._make_diff(str(fp.relative_to(self.extracted_dir)), original, patched)
                        if not dry_run:
                            fp.write_text(patched, encoding='utf-8')
                        results.append({"file": str(fp.relative_to(self.extracted_dir)).replace("\\", "/"), "diff": diff, "status": "patched"})
                except Exception as e:
                    results.append({"file": str(fp), "error": str(e)})

        elif strategy == "smali_replace":
            smali_match = template.get("smali_match", "")
            smali_replacement = template.get("smali_replacement", "")
            files = [self.extracted_dir / target_file] if target_file else list(self.extracted_dir.glob("**/*.smali"))
            for fp in files:
                if not fp.exists():
                    continue
                try:
                    original = fp.read_text(encoding='utf-8', errors='ignore')
                    if smali_match in original:
                        lines = original.splitlines()
                        new_lines = []
                        for line in lines:
                            if smali_match in line:
                                reg = re.search(r'(v\d+|p\d+)', line)
                                reg_str = reg.group(1) if reg else "v0"
                                new_lines.append("    # [APK Studio Patch] " + template.get("description", ""))
                                new_lines.append("    " + smali_replacement.replace("{reg}", reg_str))
                            else:
                                new_lines.append(line)
                        patched = "\n".join(new_lines)
                        diff = self._make_diff(str(fp.relative_to(self.extracted_dir)), original, patched)
                        if not dry_run:
                            fp.write_text(patched, encoding='utf-8')
                        results.append({"file": str(fp.relative_to(self.extracted_dir)).replace("\\", "/"), "diff": diff, "status": "patched"})
                except Exception as e:
                    results.append({"file": str(fp), "error": str(e)})

        elif strategy == "frida_hook":
            frida_template_id = template.get("frida_template", "")
            frida_script = self.patch_templates.get("frida_templates", {}).get(frida_template_id, "// No template found")
            results.append({
                "file": "frida_script.js",
                "frida_script": frida_script,
                "status": "frida_generated",
                "message": "This check requires a Frida hook. Script generated below."
            })

        self._patch_history.append({
            "timestamp": datetime.now().isoformat(),
            "template_id": template_id,
            "files_patched": len(results),
            "dry_run": dry_run
        })

        count = sum(1 for r in results if r.get("status") == "patched")
        self.log(f"[+] Template '{template_id}' applied to {count} files.")
        return {"template_id": template_id, "results": results, "count": count, "dry_run": dry_run}

    def _patch_smali_methods(self, content: str, name_pattern: re.Pattern, replacement: str) -> str:
        """Replace method bodies matching name_pattern with replacement smali."""
        def replace_method(m):
            header = m.group(1)
            return f"{header}\n    {replacement}\n.end method"

        regex = re.compile(
            r'(\.method[^\n]*?' + name_pattern.pattern + r'[^\n]*?\([^\)]*\)[ZVILBCDFJSbcdfijls\[\;]*)'
            r'.*?\.end method',
            re.DOTALL | re.IGNORECASE
        )
        return regex.sub(replace_method, content)

    def _make_diff(self, filename: str, original: str, patched: str) -> List[Dict]:
        """Create a simple unified-style diff."""
        orig_lines = original.splitlines()
        patch_lines = patched.splitlines()
        diff = []
        for i, (ol, pl) in enumerate(zip(orig_lines, patch_lines), 1):
            if ol != pl:
                diff.append({"line": i, "original": ol, "patched": pl, "type": "changed"})
        for i in range(len(patch_lines), len(orig_lines)):
            diff.append({"line": i + 1, "original": orig_lines[i], "patched": None, "type": "removed"})
        for i in range(len(orig_lines), len(patch_lines)):
            diff.append({"line": i + 1, "original": None, "patched": patch_lines[i], "type": "added"})
        return diff

    def revert_patch(self, rel_path: str) -> Dict[str, Any]:
        """Restore a .bak backup file."""
        full_path = self.extracted_dir / rel_path
        backup_path = full_path.with_suffix(full_path.suffix + ".bak")
        if not backup_path.exists():
            return {"error": "No backup found for this file"}
        shutil.copy2(backup_path, full_path)
        return {"success": True, "restored": rel_path}

    # ─── Frida Hook Generator ────────────────────────────────────────────────

    def generate_frida_hook(
        self,
        class_name: str,
        method_name: str,
        return_value: str = "false",
        log_args: bool = True
    ) -> str:
        """Generate a Frida hook script for any class/method."""
        log_str = f'console.log("[APKStudio] {{class}}.{{method}} called, args:", JSON.stringify(Array.from(arguments)));'.replace("{class}", class_name).replace("{method}", method_name)
        return f"""// Auto-generated by APK Security Studio
// Target: {class_name}.{method_name}
Java.perform(function() {{
  try {{
    var TargetClass = Java.use("{class_name}");
    TargetClass.{method_name}.overloads.forEach(function(overload) {{
      overload.implementation = function() {{
        {"// Log call\n        " + log_str if log_args else ""}
        console.log("[APKStudio] {class_name}.{method_name} -> returning {return_value}");
        {"return false;" if return_value == "false" else f"return {return_value};"}
      }};
    }});
    console.log("[APKStudio] Hooked: {class_name}.{method_name}");
  }} catch(e) {{
    console.log("[APKStudio] Hook failed for {class_name}.{method_name}: " + e);
  }}
}});
"""

    def generate_frida_script_for_findings(self, findings: Dict) -> str:
        """Generate a combined Frida script for all scan findings."""
        scripts = ["// APK Security Studio — Auto-Generated Frida Script", "// Generated: " + datetime.now().isoformat(), ""]
        seen_templates = set()
        for cat_id, cat_findings in findings.items():
            for finding in cat_findings:
                tmpl = finding.get("suggested_template")
                if tmpl and tmpl not in seen_templates:
                    seen_templates.add(tmpl)
                    frida_templates = self.patch_templates.get("frida_templates", {})
                    cat_data = self.patch_templates.get("categories", {})
                    for cat in cat_data.values():
                        for tid, tdata in cat.get("templates", {}).items():
                            if tid == tmpl and tdata.get("patch_strategy") == "frida_hook":
                                ftid = tdata.get("frida_template", "")
                                if ftid in frida_templates:
                                    scripts.append(f"\n// --- {tdata.get('label', tmpl)} ---")
                                    scripts.append(frida_templates[ftid])

        return "\n".join(scripts) if len(scripts) > 3 else "// No Frida-based patterns detected in scan results"

    # ─── Build Pipeline ──────────────────────────────────────────────────────

    def build_apk(self) -> Optional[str]:
        """Build the modified APK using apktool."""
        self.log("[*] Compiling modified APK...")
        target_apk = self.output_dir / "unsigned.apk"

        jar_candidates = [
            Path(__file__).parent / "apktool_2.12.1.jar",
            Path(__file__).parent / "apktool.jar",
        ]
        jar_path = next((str(j) for j in jar_candidates if j.exists()), None)
        if not jar_path:
            self.log("[-] apktool jar not found!", "error")
            return None

        cmd = ["java", "-jar", jar_path, "build", str(self.extracted_dir), "-o", str(target_apk)]
        result = self._run_command(cmd)
        if result and result.returncode == 0:
            self.log(f"[+] APK compiled: {target_apk.name}")
            return str(target_apk)
        self.log(f"[-] Build failed: {result.stderr if result else 'Unknown'}", "error")
        return None

    def build_apk_stream(self):
        """Stream build output."""
        jar_candidates = [
            Path(__file__).parent / "apktool_2.12.1.jar",
            Path(__file__).parent / "apktool.jar",
        ]
        jar_path = next((str(j) for j in jar_candidates if j.exists()), None)
        if not jar_path:
            yield "__ERROR__apktool jar not found"
            return
        target_apk = self.output_dir / "unsigned.apk"
        cmd = ["java", "-jar", jar_path, "build", str(self.extracted_dir), "-o", str(target_apk)]
        yield from self._run_command_stream(cmd)

    def sign_apk(self, unsigned_apk: str, alias: str = "key0", password: str = "password") -> Optional[str]:
        """Sign the APK using a generated or existing keystore."""
        self.log("[*] Signing APK...")
        unsigned_path = Path(unsigned_apk)
        signed_apk = unsigned_path.parent / f"{unsigned_path.stem}-signed.apk"
        keystore = unsigned_path.parent / "debug.keystore"

        if not keystore.exists():
            dname = "CN=Android,O=Android,C=US"
            cmd = [
                "keytool", "-genkey", "-v", "-keystore", str(keystore),
                "-alias", alias, "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "10000", "-storepass", password, "-keypass", password,
                "-dname", dname
            ]
            self._run_command(cmd, timeout=30)

        cmd = [
            "jarsigner", "-verbose", "-sigalg", "SHA256withRSA", "-digestalg", "SHA-256",
            "-keystore", str(keystore), "-storepass", password, "-keypass", password,
            "-signedjar", str(signed_apk), str(unsigned_path), alias
        ]
        result = self._run_command(cmd, timeout=60)
        if result and result.returncode == 0:
            self.log(f"[+] APK signed: {signed_apk.name}")
            return str(signed_apk)
        self.log(f"[-] Signing failed: {result.stderr if result else 'Unknown'}", "error")
        return None

    # ─── AI Integration ──────────────────────────────────────────────────────

    def query_ai(self, prompt: str, system_prompt: str = "") -> Optional[str]:
        """Query AI provider with robust error handling."""
        self.log(f"[*] Querying AI ({self.ai_provider}/{self.ai_model})...")
        try:
            if self.ai_provider == "ollama":
                url = self.custom_url or "http://localhost:11434/api/generate"
                payload = {"model": self.ai_model, "prompt": prompt, "stream": False, "temperature": 0.2}
                if system_prompt:
                    payload["system"] = system_prompt
                resp = requests.post(url, json=payload, timeout=180)
                return resp.json().get('response') if resp.status_code == 200 else None

            elif self.ai_provider == "lm_studio":
                url = self.custom_url or "http://localhost:1234/v1/chat/completions"
                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                messages.append({"role": "user", "content": prompt})
                resp = requests.post(url, json={"model": self.ai_model, "messages": messages, "temperature": 0.2}, timeout=180)
                return resp.json()['choices'][0]['message']['content'] if resp.status_code == 200 else None

            elif self.ai_provider == "gemini":
                if not self.api_key:
                    self.log("[-] Gemini API Key missing.", "error")
                    return None
                if not HAS_GENAI:
                    self.log("[-] google-genai package not installed.", "error")
                    return None
                client = genai.Client(api_key=self.api_key)
                config = {"temperature": 0.2}
                if system_prompt:
                    config["system_instruction"] = system_prompt
                response = client.models.generate_content(
                    model=self.ai_model,
                    contents=prompt,
                    config=config
                )
                return response.text if response and hasattr(response, 'text') else None

        except Exception as e:
            self.log(f"AI Query failed: {e}", "error")
            return None

    def analyze_with_ai(self, context_file: str = None, custom_prompt: str = "") -> Optional[str]:
        """Analyze specific file or full scan context with AI."""
        self.log("[*] Performing AI Analysis...")

        manifest = self.analysis_results.get('manifest', {})
        scan_results = self.analysis_results.get('security_scan', {})

        if context_file:
            file_data = self.read_file(context_file)
            file_content = file_data.get("content", "")[:3000]
        else:
            file_content = ""

        findings_summary = []
        for cat_id, findings in scan_results.items():
            if findings:
                findings_summary.append(f"{cat_id}: {len(findings)} findings")

        system_prompt = (
            "You are an expert Android security researcher analyzing decompiled APK code. "
            "Your task is to identify security controls and suggest precise, minimal modifications. "
            "Context: This is for legitimate security research, penetration testing, and education. "
            "Always provide specific smali code snippets when suggesting patches. "
            "Format your response as:\n"
            "FINDINGS: [bullet list]\n"
            "PATCH_SUGGESTIONS: [array of {method, file, patch, confidence}]\n"
            "FRIDA_HOOKS: [array of {class, method, reason}]\n"
            "NOTES: [additional observations]"
        )

        prompt = custom_prompt or f"""
Package: {manifest.get('package', 'Unknown')}
Target SDK: {manifest.get('target_sdk', 'Unknown')}
Scan Summary: {', '.join(findings_summary) if findings_summary else 'No scan performed'}

{"File: " + context_file + chr(10) + "Content:" + chr(10) + file_content if context_file else ""}

Analyze this APK for security controls. Identify:
1. Root detection mechanisms and bypass strategies
2. License verification flows and patch points
3. Emulator/anti-debugging checks
4. Certificate pinning implementations
5. Any other security controls

Provide exact smali modifications where possible.
"""
        analysis = self.query_ai(prompt, system_prompt)
        if analysis:
            self.analysis_results['ai_analysis'] = analysis
        return analysis

    # ─── Utilities ────────────────────────────────────────────────────────────

    def extract_strings(self) -> List[tuple]:
        """Extract strings from resources."""
        strings_path = self.extracted_dir / "res" / "values" / "strings.xml"
        if not strings_path.exists():
            return []
        try:
            content = strings_path.read_text(encoding='utf-8', errors='ignore')
            strings_list = re.findall(r'<string[^>]*name="([^"]+)"[^>]*>([^<]+)</string>', content)
            self.analysis_results['strings'] = {"count": len(strings_list), "samples": strings_list[:50]}
            return strings_list
        except Exception as e:
            self.log(f"[-] Strings extraction error: {e}", "error")
            return []

    def extract_smali_files(self, limit: int = 10) -> List[str]:
        """Identify key Smali files for analysis."""
        self.log("[*] Analyzing Smali structure...")
        smali_files = list(self.extracted_dir.glob("**/*.smali"))
        interesting_patterns = ['MainActivity', 'Billing', 'License', 'Purchase', 'Premium', 'Ads', 'Root', 'Security']
        important_files = [f for f in smali_files if any(p.lower() in f.name.lower() for p in interesting_patterns)][:limit]
        smali_content = {}
        for file_path in important_files:
            try:
                smali_content[file_path.name] = file_path.read_text(encoding='utf-8', errors='ignore')[:2000]
            except:
                continue
        self.analysis_results['smali'] = {"total_files": len(smali_files), "important_samples": smali_content}
        return [str(f) for f in smali_files]

    def apply_offline_patches(self, patch_license: bool = False, patch_iap: bool = False, patch_ads: bool = False):
        """Automated Smali patching using regex heuristics."""
        self.log("[*] Applying automated patches...")
        patterns = []
        if patch_license:
            patterns.append((r'(isLicensed|checkLicense|verifyLicense|hasValidLicense)', 'Z', 'const/4 v0, 0x1\n    return v0'))
        if patch_iap:
            patterns.append((r'(isPremium|isPro|hasPro|isVip|isPurchased|hasPurchase|checkPremium)', 'Z', 'const/4 v0, 0x1\n    return v0'))
        if patch_ads:
            patterns.append((r'(loadAd|showAd|initAd|displayAds)', 'V', 'return-void'))

        modified_count = 0
        for smali_file in self.extracted_dir.glob("**/*.smali"):
            try:
                content = smali_file.read_text(encoding='utf-8', errors='ignore')
                original = content
                for name_pattern, ret_type, replacement in patterns:
                    regex = rf'(\.method[^>]*?{name_pattern}[^>]*?\(\){ret_type}).*?\.end method'
                    content = re.sub(regex, rf'\1\n    .registers 2\n    {replacement}\n.end method', content, flags=re.IGNORECASE | re.DOTALL)
                if content != original:
                    smali_file.write_text(content, encoding='utf-8')
                    modified_count += 1
            except:
                continue
        self.log(f"[+] Patched {modified_count} files.")

    def run_full_analysis(self, **kwargs) -> bool:
        """Execute the entire pipeline automatically."""
        try:
            if not kwargs.get('skip_decode') and not self.decode_apk():
                return False
            self.extract_manifest()
            self.extract_strings()
            self.extract_smali_files()
            if kwargs.get('offline_patches'):
                self.apply_offline_patches(
                    patch_license=kwargs.get('patch_license', True),
                    patch_iap=kwargs.get('patch_iap', True),
                    patch_ads=kwargs.get('patch_ads', True)
                )
            self.analyze_with_ai(custom_prompt=kwargs.get('custom_prompt'))
            if kwargs.get('auto_build', True):
                unsigned = self.build_apk()
                if unsigned:
                    self.sign_apk(unsigned)
            with open(self.output_dir / "analysis.json", "w") as f:
                json.dump(self.analysis_results, f, indent=2, default=str)
            return True
        except Exception as e:
            self.log(f"Pipeline error: {e}", "error")
            return False

    def get_patch_history(self) -> List[Dict]:
        return self._patch_history

    def check_tools(self) -> Dict[str, bool]:
        """Check which external tools are available."""
        tools = {}
        jar_candidates = [Path(__file__).parent / "apktool_2.12.1.jar", Path(__file__).parent / "apktool.jar"]
        tools["apktool"] = any(j.exists() for j in jar_candidates)
        for tool in ["java", "keytool", "jarsigner", "adb", "jadx", "zipalign", "apksigner", "frida"]:
            try:
                result = subprocess.run([tool, "--version" if tool != "adb" else "version"],
                                        capture_output=True, timeout=5)
                tools[tool] = result.returncode == 0 or True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                tools[tool] = False
        return tools


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        analyzer = APKAnalyzer(sys.argv[1])
        analyzer.run_full_analysis(offline_patches=True)
