import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import os
import requests
import json
from pathlib import Path
from AI_Revserse_Engineering_APK import APKAnalyzer

# Set app appearance
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("AI Reverse Engineering Studio")
        self.geometry("1200x850")

        # Grid Configuration
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.create_sidebar()
        self.create_main_frame()

        self.apk_path = None
        self.base_output_dir = Path(os.getcwd()) / "apk_analysis_output"
        self.base_output_dir.mkdir(exist_ok=True)

    def create_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=280, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(10, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="APK Studio Pro", font=ctk.CTkFont(size=24, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # Provider Selection
        ctk.CTkLabel(self.sidebar_frame, text="AI Provider:", anchor="w").grid(row=1, column=0, padx=20, pady=(10, 0), sticky="w")
        self.provider_optionmenu = ctk.CTkOptionMenu(self.sidebar_frame, values=["Ollama", "LM Studio", "Gemini"], command=self.on_provider_change)
        self.provider_optionmenu.grid(row=2, column=0, padx=20, pady=(5, 10))
        self.provider_optionmenu.set("Ollama")

        # Model Selection
        ctk.CTkLabel(self.sidebar_frame, text="AI Model:", anchor="w").grid(row=3, column=0, padx=20, pady=(10, 0), sticky="w")
        self.model_optionmenu = ctk.CTkOptionMenu(self.sidebar_frame, values=["Loading..."])
        self.model_optionmenu.grid(row=4, column=0, padx=20, pady=(5, 10))

        # API Key / Url
        ctk.CTkLabel(self.sidebar_frame, text="API Key / URL:", anchor="w").grid(row=5, column=0, padx=20, pady=(10, 0), sticky="w")
        self.api_entry = ctk.CTkEntry(self.sidebar_frame, placeholder_text="Optional", show="*")
        self.api_entry.grid(row=6, column=0, padx=20, pady=(5, 10))

        # Action Buttons
        self.fetch_models_btn = ctk.CTkButton(self.sidebar_frame, text="Refresh Models", command=self.refresh_models, height=32)
        self.fetch_models_btn.grid(row=7, column=0, padx=20, pady=(10, 20))

        self.sep = ctk.CTkFrame(self.sidebar_frame, height=2, fg_color="gray30")
        self.sep.grid(row=8, column=0, sticky="ew", padx=20, pady=10)

        self.actions_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        self.actions_frame.grid(row=9, column=0, padx=20, pady=10, sticky="ew")

        self.btn_auto = ctk.CTkButton(self.actions_frame, text="AUTO COMPLETE (One-Click)", command=lambda: self.start_action_thread("auto"), fg_color="#1f538d", hover_color="#14375e", height=45, font=ctk.CTkFont(weight="bold"))
        self.btn_auto.pack(pady=10, fill="x")

        buttons = [
            ("1. Decode APK", "decode"),
            ("2. AI Analysis & Patch", "ai_fix"),
            ("3. Build APK", "compile"),
            ("4. Sign APK", "sign")
        ]
        
        for text, action in buttons:
            btn = ctk.CTkButton(self.actions_frame, text=text, command=lambda a=action: self.start_action_thread(a), height=32, fg_color="gray30", hover_color="gray40")
            btn.pack(pady=4, fill="x")

        self.refresh_models()

    def create_main_frame(self):
        self.main_frame = ctk.CTkFrame(self, corner_radius=10)
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(2, weight=1)

        # File Selection Area
        self.top_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.top_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        self.top_frame.grid_columnconfigure(1, weight=1)

        self.select_apk_btn = ctk.CTkButton(self.top_frame, text="Select Target APK", command=self.select_apk, width=160)
        self.select_apk_btn.grid(row=0, column=0, padx=(0, 10), pady=5)
        self.apk_label = ctk.CTkLabel(self.top_frame, text="No APK selected", text_color="gray60")
        self.apk_label.grid(row=0, column=1, sticky="w")

        # Tabs
        self.tabview = ctk.CTkTabview(self.main_frame)
        self.tabview.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        self.tabview.add("Optimization Prompt")
        self.tabview.add("Automation Settings")
        self.tabview.add("File Explorer")

        # Prompt Tab
        self.prompt_text = ctk.CTkTextbox(self.tabview.tab("Optimization Prompt"), font=("Segoe UI", 13))
        self.prompt_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.prompt_text.insert("0.0", "Analyze the application to identify and bypass license checks, remove advertisements, and unlock all premium functionality. Provide direct Smali modifications.")

        # Settings Tab
        tab_settings = self.tabview.tab("Automation Settings")
        tab_settings.grid_columnconfigure((0, 1), weight=1)
        
        self.patch_license_var = ctk.BooleanVar(value=True)
        self.patch_license_cb = ctk.CTkCheckBox(tab_settings, text="Auto-Bypass License Checks", variable=self.patch_license_var)
        self.patch_license_cb.grid(row=0, column=0, padx=20, pady=15, sticky="w")

        self.patch_iap_var = ctk.BooleanVar(value=True)
        self.patch_iap_cb = ctk.CTkCheckBox(tab_settings, text="Auto-Unlock In-App Features", variable=self.patch_iap_var)
        self.patch_iap_cb.grid(row=1, column=0, padx=20, pady=15, sticky="w")

        self.patch_ads_var = ctk.BooleanVar(value=True)
        self.patch_ads_cb = ctk.CTkCheckBox(tab_settings, text="Auto-Remove Advertisements", variable=self.patch_ads_var)
        self.patch_ads_cb.grid(row=2, column=0, padx=20, pady=15, sticky="w")

        self.auto_build_var = ctk.BooleanVar(value=True)
        self.auto_build_cb = ctk.CTkCheckBox(tab_settings, text="Build & Sign Automatically", variable=self.auto_build_var)
        self.auto_build_cb.grid(row=0, column=1, padx=20, pady=15, sticky="w")

        # Explorer Tab
        tab_explorer = self.tabview.tab("File Explorer")
        tab_explorer.grid_columnconfigure(1, weight=1)
        tab_explorer.grid_rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(tab_explorer)
        self.tree.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.tree.heading("#0", text="APK Contents", anchor="w")
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        self.file_editor = ctk.CTkTextbox(tab_explorer, font=("Consolas", 12))
        self.file_editor.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)

        # Console Output
        self.console_text = ctk.CTkTextbox(self.main_frame, font=("Consolas", 11), fg_color="#101010", text_color="#00FF00")
        self.console_text.grid(row=3, column=0, padx=10, pady=(0, 10), sticky="nsew")

    def log_to_console(self, message):
        def _log():
            self.console_text.insert(tk.END, f"[{threading.current_thread().name}] {message}\n")
            self.console_text.see(tk.END)
        self.after(0, _log)

    def on_provider_change(self, choice):
        if choice == "Gemini":
            self.model_optionmenu.configure(values=["gemini-1.5-pro", "gemini-1.5-flash"])
            self.model_optionmenu.set("gemini-1.5-pro")
        else:
            self.refresh_models()

    def refresh_models(self):
        provider = self.provider_optionmenu.get()
        if provider == "Gemini": return

        def fetch():
            try:
                if provider == "Ollama":
                    url = self.api_entry.get() or "http://localhost:11434"
                    resp = requests.get(f"{url}/api/tags", timeout=5)
                    models = [m["name"] for m in resp.json().get("models", [])]
                elif provider == "LM Studio":
                    url = self.api_entry.get() or "http://localhost:1234"
                    resp = requests.get(f"{url}/v1/models", timeout=5)
                    models = [m["id"] for m in resp.json().get("data", [])]
                else: models = []
                
                if not models: models = ["No models found"]
                self.after(0, lambda: self.model_optionmenu.configure(values=models))
                self.after(0, lambda: self.model_optionmenu.set(models[0]))
            except:
                self.after(0, lambda: self.model_optionmenu.configure(values=["Connection Error"]))

        threading.Thread(target=fetch, daemon=True).start()

    def select_apk(self):
        file_path = filedialog.askopenfilename(filetypes=[("APK Files", "*.apk")])
        if file_path:
            self.apk_path = Path(file_path)
            self.apk_label.configure(text=self.apk_path.name, text_color="white")

    def on_tree_select(self, event):
        item = self.tree.selection()
        if not item: return
        path = self.tree.item(item[0])["values"][0]
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    self.file_editor.delete("0.0", tk.END)
                    self.file_editor.insert("0.0", f.read())
            except: pass

    def populate_tree(self, path, parent=""):
        if parent == "": self.tree.delete(*self.tree.get_children())
        try:
            items = os.listdir(path)
            items.sort(key=lambda x: (not os.path.isdir(os.path.join(path, x)), x.lower()))
            for item in items:
                abs_p = os.path.join(path, item)
                node = self.tree.insert(parent, "end", text=item, values=(abs_p,))
                if os.path.isdir(abs_p): self.populate_tree(abs_p, node)
        except: pass

    def start_action_thread(self, action):
        if not self.apk_path:
            messagebox.showwarning("Selection Required", "Please select a target APK file first.")
            return
        
        # Disable UI
        self.btn_auto.configure(state="disabled")
        threading.Thread(target=self.run_action, args=(action,), daemon=True).start()

    def run_action(self, action):
        try:
            self.log_to_console(f"Starting {action.upper()} operation...")
            
            output_dir = self.base_output_dir / self.apk_path.stem
            analyzer = APKAnalyzer(
                apk_path=str(self.apk_path),
                output_dir=str(output_dir),
                ai_provider=self.provider_optionmenu.get(),
                ai_model=self.model_optionmenu.get(),
                api_key=self.api_entry.get(),
                custom_url=self.api_entry.get() if self.provider_optionmenu.get() != "Gemini" else "",
                log_callback=self.log_to_console
            )

            if action == "auto":
                analyzer.run_full_analysis(
                    offline_patches=True,
                    patch_license=self.patch_license_var.get(),
                    patch_iap=self.patch_iap_var.get(),
                    patch_ads=self.patch_ads_var.get(),
                    auto_build=self.auto_build_var.get(),
                    custom_prompt=self.prompt_text.get("0.0", tk.END).strip()
                )
                self.after(0, lambda: self.populate_tree(str(analyzer.extracted_dir)))
                self.log_to_console("--- AUTO COMPLETE FINISHED ---")

            elif action == "decode":
                if analyzer.decode_apk():
                    self.after(0, lambda: self.populate_tree(str(analyzer.extracted_dir)))

            elif action == "ai_fix":
                analyzer.extract_manifest()
                analyzer.extract_smali_files()
                analyzer.apply_offline_patches(self.patch_license_var.get(), self.patch_iap_var.get(), self.patch_ads_var.get())
                analyzer.analyze_with_ai(custom_prompt=self.prompt_text.get("0.0", tk.END).strip())

            elif action == "compile":
                analyzer.build_apk()

            elif action == "sign":
                unsigned = output_dir / "unsigned.apk"
                if unsigned.exists():
                    analyzer.sign_apk(str(unsigned))
                else:
                    self.log_to_console("Error: unsigned.apk not found. Build first.")

        except Exception as e:
            self.log_to_console(f"CRITICAL ERROR: {e}")
        finally:
            self.after(0, lambda: self.btn_auto.configure(state="normal"))

if __name__ == "__main__":
    app = App()
    app.mainloop()
