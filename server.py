"""
APK Security Studio — Flask + SocketIO Backend Server
Serves the web IDE and wraps the APKAnalyzer engine via REST API + WebSockets.
"""
import os
import sys
import json
import uuid
import threading
import shutil
from pathlib import Path
from datetime import datetime

from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from werkzeug.utils import secure_filename

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))
from AI_Revserse_Engineering_APK import APKAnalyzer

# ─── App Configuration ────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent
WEB_DIR = BASE_DIR / "web"
UPLOAD_DIR = BASE_DIR / "apk_analysis_output" / "uploads"
PROJECTS_DIR = BASE_DIR / "apk_analysis_output" / "projects"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
PROJECTS_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'apk-security-studio-key-2024'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max APK

CORS(app, resources={r"/api/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', logger=False, engineio_logger=False)

# ─── Session State ────────────────────────────────────────────────────────────

projects: dict[str, dict] = {}  # project_id -> {analyzer, meta}


def get_project(project_id: str) -> APKAnalyzer | None:
    proj = projects.get(project_id)
    return proj["analyzer"] if proj else None


def make_log_callback(project_id: str):
    """Returns a log callback that emits to the WebSocket room."""
    def cb(msg):
        socketio.emit('console_log', {
            'project_id': project_id,
            'message': msg,
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }, namespace='/')
    return cb


@app.route('/')
def index():
    return send_from_directory(str(WEB_DIR), 'index.html')


@app.route('/style.css')
def serve_css():
    return send_from_directory(str(WEB_DIR), 'style.css')


@app.route('/app.js')
def serve_appjs():
    return send_from_directory(str(WEB_DIR), 'app.js')


@app.route('/api.js')
def serve_apijs():
    return send_from_directory(str(WEB_DIR), 'api.js')


@app.route('/monaco-setup.js')
def serve_monaco():
    return send_from_directory(str(WEB_DIR), 'monaco-setup.js')



# ─── Tool Health Check ────────────────────────────────────────────────────────

@app.route('/api/health')
def health():
    dummy = APKAnalyzer.__new__(APKAnalyzer)
    dummy.__dict__.update({
        'apk_path': Path('.'), 'output_dir': Path('.'),
        'extracted_dir': Path('.'), 'log_callback': None,
        'patch_templates': {}
    })
    tools = {}
    import subprocess
    jar_candidates = [BASE_DIR / "apktool_2.12.1.jar", BASE_DIR / "apktool.jar"]
    tools["apktool"] = any(j.exists() for j in jar_candidates)
    for tool in ["java", "keytool", "jarsigner", "adb", "frida"]:
        try:
            r = subprocess.run([tool, "-version" if tool in ("java","keytool","jarsigner") else "version"],
                               capture_output=True, timeout=5)
            tools[tool] = True
        except FileNotFoundError:
            tools[tool] = False
        except Exception:
            tools[tool] = False
    return jsonify({"status": "ok", "tools": tools, "version": "1.0.0"})


# ─── Project Management ───────────────────────────────────────────────────────

@app.route('/api/projects', methods=['GET'])
def list_projects():
    result = []
    for pid, proj in projects.items():
        result.append({
            "id": pid,
            "name": proj["meta"].get("apk_name", "Unknown"),
            "package": proj["meta"].get("package", ""),
            "created": proj["meta"].get("created", ""),
            "has_scan": bool(proj["analyzer"].analysis_results.get("security_scan"))
        })
    return jsonify(result)


@app.route('/api/projects/<project_id>', methods=['DELETE'])
def delete_project(project_id):
    if project_id in projects:
        proj = projects.pop(project_id)
        try:
            shutil.rmtree(str(proj["analyzer"].output_dir), ignore_errors=True)
        except Exception:
            pass
        return jsonify({"success": True})
    return jsonify({"error": "Project not found"}), 404


# ─── APK Upload ───────────────────────────────────────────────────────────────

@app.route('/api/upload', methods=['POST'])
def upload_apk():
    if 'apk' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files['apk']
    if not f.filename.endswith('.apk'):
        return jsonify({"error": "File must be an .apk"}), 400

    project_id = str(uuid.uuid4())[:8]
    apk_name = secure_filename(f.filename)
    apk_path = UPLOAD_DIR / f"{project_id}_{apk_name}"
    output_dir = PROJECTS_DIR / project_id

    f.save(str(apk_path))

    ai_provider = request.form.get('ai_provider', 'ollama')
    ai_model = request.form.get('ai_model', 'mistral')
    api_key = request.form.get('api_key', '')
    custom_url = request.form.get('custom_url', '')

    analyzer = APKAnalyzer(
        apk_path=str(apk_path),
        output_dir=str(output_dir),
        ai_provider=ai_provider,
        ai_model=ai_model,
        api_key=api_key,
        custom_url=custom_url,
        log_callback=make_log_callback(project_id)
    )

    projects[project_id] = {
        "analyzer": analyzer,
        "meta": {
            "apk_name": apk_name,
            "apk_path": str(apk_path),
            "package": "",
            "created": datetime.now().isoformat(),
            "project_id": project_id
        }
    }

    return jsonify({
        "project_id": project_id,
        "apk_name": apk_name,
        "size": apk_path.stat().st_size
    })


# ─── Decode ───────────────────────────────────────────────────────────────────

@app.route('/api/<project_id>/decode', methods=['POST'])
def decode_apk(project_id):
    analyzer = get_project(project_id)
    if not analyzer:
        return jsonify({"error": "Project not found"}), 404

    def run():
        analyzer.log(f"[*] Starting decode: {analyzer.apk_path.name}")
        success = analyzer.decode_apk()
        if success:
            manifest = analyzer.extract_manifest()
            analyzer.extract_strings()
            if manifest and project_id in projects:
                projects[project_id]["meta"]["package"] = manifest.get("package", "")
            analyzer.log("[+] Ready. Files available in project tree.")
            socketio.emit('decode_complete', {
                'project_id': project_id,
                'success': True,
                'manifest': manifest
            })
        else:
            socketio.emit('decode_complete', {'project_id': project_id, 'success': False})

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "decoding", "project_id": project_id})


# ─── File Tree ────────────────────────────────────────────────────────────────

@app.route('/api/<project_id>/tree')
def file_tree(project_id):
    analyzer = get_project(project_id)
    if not analyzer:
        return jsonify({"error": "Project not found"}), 404
    if not analyzer.extracted_dir.exists():
        return jsonify({"error": "APK not yet decoded"}), 400
    tree = analyzer.get_file_tree()
    return jsonify(tree)


# ─── File Read/Write ──────────────────────────────────────────────────────────

@app.route('/api/<project_id>/file', methods=['GET'])
def read_file(project_id):
    analyzer = get_project(project_id)
    if not analyzer:
        return jsonify({"error": "Project not found"}), 404
    rel_path = request.args.get('path', '')
    if not rel_path:
        return jsonify({"error": "Path required"}), 400
    return jsonify(analyzer.read_file(rel_path))


@app.route('/api/<project_id>/file', methods=['PUT'])
def write_file(project_id):
    analyzer = get_project(project_id)
    if not analyzer:
        return jsonify({"error": "Project not found"}), 404
    data = request.json or {}
    rel_path = data.get('path', '')
    content = data.get('content', '')
    if not rel_path:
        return jsonify({"error": "Path required"}), 400
    return jsonify(analyzer.write_file(rel_path, content))


@app.route('/api/<project_id>/file/revert', methods=['POST'])
def revert_file(project_id):
    analyzer = get_project(project_id)
    if not analyzer:
        return jsonify({"error": "Project not found"}), 404
    data = request.json or {}
    return jsonify(analyzer.revert_patch(data.get('path', '')))


# ─── Security Scan ────────────────────────────────────────────────────────────

@app.route('/api/<project_id>/scan', methods=['POST'])
def security_scan(project_id):
    analyzer = get_project(project_id)
    if not analyzer:
        return jsonify({"error": "Project not found"}), 404
    if not analyzer.extracted_dir.exists():
        return jsonify({"error": "APK not yet decoded"}), 400

    def run():
        analyzer.log("[*] Starting security pattern scan...")
        findings = analyzer.scan_security_patterns()
        total = sum(len(v) for v in findings.values())
        analyzer.log(f"[+] Scan complete: {total} findings across {len(findings)} categories.")
        socketio.emit('scan_complete', {
            'project_id': project_id,
            'findings': findings,
            'total': total
        })

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "scanning"})


@app.route('/api/<project_id>/scan/results')
def scan_results(project_id):
    analyzer = get_project(project_id)
    if not analyzer:
        return jsonify({"error": "Project not found"}), 404
    return jsonify(analyzer.analysis_results.get("security_scan", {}))


# ─── Patch Engine ─────────────────────────────────────────────────────────────

@app.route('/api/<project_id>/patch', methods=['POST'])
def apply_patch(project_id):
    analyzer = get_project(project_id)
    if not analyzer:
        return jsonify({"error": "Project not found"}), 404

    data = request.json or {}
    template_id = data.get('template_id')
    target_file = data.get('target_file')
    dry_run = data.get('dry_run', False)

    if not template_id:
        return jsonify({"error": "template_id required"}), 400

    result = analyzer.apply_patch_template(template_id, target_file, dry_run=dry_run)
    if not dry_run:
        analyzer.log(f"[+] Patch '{template_id}' applied: {result.get('count', 0)} files modified.")
    return jsonify(result)


@app.route('/api/<project_id>/patch/batch', methods=['POST'])
def apply_patch_batch(project_id):
    """Apply multiple patch templates at once."""
    analyzer = get_project(project_id)
    if not analyzer:
        return jsonify({"error": "Project not found"}), 404

    data = request.json or {}
    template_ids = data.get('template_ids', [])
    dry_run = data.get('dry_run', False)

    all_results = {}
    for tid in template_ids:
        all_results[tid] = analyzer.apply_patch_template(tid, dry_run=dry_run)

    total = sum(r.get('count', 0) for r in all_results.values())
    if not dry_run:
        analyzer.log(f"[+] Batch patch complete: {total} total files modified across {len(template_ids)} templates.")
    return jsonify({"results": all_results, "total_files": total, "dry_run": dry_run})


@app.route('/api/<project_id>/patch/history')
def patch_history(project_id):
    analyzer = get_project(project_id)
    if not analyzer:
        return jsonify({"error": "Project not found"}), 404
    return jsonify(analyzer.get_patch_history())


@app.route('/api/patch-templates')
def get_templates():
    templates_path = BASE_DIR / "patch_templates.json"
    if templates_path.exists():
        with open(templates_path) as f:
            return jsonify(json.load(f))
    return jsonify({})


# ─── Frida Hook Generator ─────────────────────────────────────────────────────

@app.route('/api/<project_id>/frida/hook', methods=['POST'])
def generate_frida_hook(project_id):
    analyzer = get_project(project_id)
    if not analyzer:
        return jsonify({"error": "Project not found"}), 404

    data = request.json or {}
    class_name = data.get('class_name', '')
    method_name = data.get('method_name', '')
    return_value = data.get('return_value', 'false')

    if not class_name or not method_name:
        return jsonify({"error": "class_name and method_name required"}), 400

    script = analyzer.generate_frida_hook(class_name, method_name, return_value)
    return jsonify({"script": script, "class": class_name, "method": method_name})


@app.route('/api/<project_id>/frida/from-scan', methods=['POST'])
def frida_from_scan(project_id):
    analyzer = get_project(project_id)
    if not analyzer:
        return jsonify({"error": "Project not found"}), 404

    findings = analyzer.analysis_results.get("security_scan", {})
    script = analyzer.generate_frida_script_for_findings(findings)
    return jsonify({"script": script})


# ─── Build Pipeline ───────────────────────────────────────────────────────────

@app.route('/api/<project_id>/build', methods=['POST'])
def build_apk(project_id):
    analyzer = get_project(project_id)
    if not analyzer:
        return jsonify({"error": "Project not found"}), 404

    def run():
        analyzer.log("[*] Starting APK build pipeline...")
        unsigned = analyzer.build_apk()
        if unsigned:
            analyzer.log("[*] Build succeeded. Signing APK...")
            signed = analyzer.sign_apk(unsigned)
            if signed:
                analyzer.log(f"[+] Build complete! Signed APK: {Path(signed).name}")
                socketio.emit('build_complete', {
                    'project_id': project_id,
                    'success': True,
                    'signed_apk': Path(signed).name
                })
            else:
                analyzer.log("[-] Signing failed.")
                socketio.emit('build_complete', {'project_id': project_id, 'success': False, 'error': 'Sign failed'})
        else:
            analyzer.log("[-] Build failed.")
            socketio.emit('build_complete', {'project_id': project_id, 'success': False, 'error': 'Build failed'})

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "building"})


@app.route('/api/<project_id>/download/<filename>')
def download_file(project_id, filename):
    analyzer = get_project(project_id)
    if not analyzer:
        return jsonify({"error": "Project not found"}), 404
    file_path = analyzer.output_dir / filename
    if not file_path.exists():
        return jsonify({"error": "File not found"}), 404
    return send_file(str(file_path), as_attachment=True, download_name=filename)


# ─── AI Integration ───────────────────────────────────────────────────────────

@app.route('/api/<project_id>/ai/analyze', methods=['POST'])
def ai_analyze(project_id):
    analyzer = get_project(project_id)
    if not analyzer:
        return jsonify({"error": "Project not found"}), 404

    data = request.json or {}
    context_file = data.get('file')
    custom_prompt = data.get('prompt', '')

    # Update AI settings if provided
    if data.get('ai_provider'):
        analyzer.ai_provider = data['ai_provider'].lower().replace(' ', '_')
    if data.get('ai_model'):
        analyzer.ai_model = data['ai_model']
    if data.get('api_key'):
        analyzer.api_key = data['api_key']
    if data.get('custom_url'):
        analyzer.custom_url = data['custom_url']

    def run():
        analyzer.log(f"[*] Querying AI ({analyzer.ai_provider}/{analyzer.ai_model})...")
        result = analyzer.analyze_with_ai(context_file=context_file, custom_prompt=custom_prompt)
        socketio.emit('ai_response', {
            'project_id': project_id,
            'response': result or "No response from AI. Check your connection settings.",
            'context_file': context_file
        })

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "analyzing"})


@app.route('/api/ai/models', methods=['GET'])
def get_ai_models():
    """Fetch available models from Ollama or LM Studio."""
    provider = request.args.get('provider', 'ollama')
    url = request.args.get('url', '')

    import requests as req
    try:
        if provider == 'ollama':
            endpoint = url or 'http://localhost:11434'
            r = req.get(f"{endpoint}/api/tags", timeout=5)
            if r.status_code == 200:
                models = [m['name'] for m in r.json().get('models', [])]
                return jsonify({"models": models})
        elif provider == 'lm_studio':
            endpoint = url or 'http://localhost:1234'
            r = req.get(f"{endpoint}/v1/models", timeout=5)
            if r.status_code == 200:
                models = [m['id'] for m in r.json().get('data', [])]
                return jsonify({"models": models})
    except Exception as e:
        return jsonify({"error": str(e), "models": []})

    return jsonify({"models": ["gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"]
                    if provider == 'gemini' else []})


# ─── Manifest / Analysis Data ─────────────────────────────────────────────────

@app.route('/api/<project_id>/manifest')
def get_manifest(project_id):
    analyzer = get_project(project_id)
    if not analyzer:
        return jsonify({"error": "Project not found"}), 404
    return jsonify(analyzer.analysis_results.get("manifest", {}))


@app.route('/api/<project_id>/analysis')
def get_analysis(project_id):
    analyzer = get_project(project_id)
    if not analyzer:
        return jsonify({"error": "Project not found"}), 404
    return jsonify(analyzer.analysis_results)


# ─── WebSocket Events ─────────────────────────────────────────────────────────

@socketio.on('connect')
def on_connect():
    emit('connected', {'status': 'APK Security Studio connected'})


@socketio.on('ping')
def on_ping():
    emit('pong', {'time': datetime.now().isoformat()})


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 60)
    print("  APK Security Studio — Web Server")
    print("  http://localhost:5000")
    print("=" * 60)
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
