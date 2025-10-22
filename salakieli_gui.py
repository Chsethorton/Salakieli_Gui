#simple Salakieli decryptor/encryptor
#Built off of necauqua's command line on Discord
#Codex for the GUI

import os
import sys
import json
import tempfile
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

DEFAULT_KEY_HEX = "536563726574734f66546865416c6c53"  # 16 bytes (128-bit)
DEFAULT_IV_HEX  = "54687265654579657341726557617463"  # 16 bytes (128-bit)

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "salakieli_gui.json")

def load_cfg():
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_cfg(cfg: dict):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass

def is_hex(s: str) -> bool:
    try:
        int(s, 16)
        return True
    except ValueError:
        return False

def validate_hex_len(name: str, s: str, want_len: int):
    if not s:
        raise ValueError(f"{name} is empty")
    if not is_hex(s):
        raise ValueError(f"{name} must be hex (0-9a-f)")
    if len(s) != want_len:
        raise ValueError(f"{name} must be {want_len} hex chars ({want_len//2} bytes)")

def which(program: str) -> str:
    if os.path.isfile(program):
        return program
    for p in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(p, program)
        if os.path.isfile(candidate):
            return candidate
        if os.name == "nt":
            candidate_exe = candidate + ".exe"
            if os.path.isfile(candidate_exe):
                return candidate_exe
    return program

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Salakieli (OpenSSL AES-128-CTR)")
        self.geometry("980x640")
        self.minsize(900, 560)

        self.cfg = load_cfg()
        self._build_ui()

    def _build_ui(self):
        pad = {"padx": 8, "pady": 6}

        settings = ttk.LabelFrame(self, text="Settings")
        settings.pack(fill="x", **pad)

        ttk.Label(settings, text="OpenSSL path").grid(row=0, column=0, sticky="w")
        self.openssl_var = tk.StringVar(value=self.cfg.get("openssl", "openssl"))
        ttk.Entry(settings, textvariable=self.openssl_var, width=40).grid(row=0, column=1, sticky="we", **pad)
        ttk.Button(settings, text="Browse…", command=self.browse_openssl).grid(row=0, column=2, sticky="w", **pad)

        ttk.Label(settings, text="Key (hex, 16 bytes)").grid(row=1, column=0, sticky="w")
        self.key_var = tk.StringVar(value=self.cfg.get("key_hex", DEFAULT_KEY_HEX))
        ttk.Entry(settings, textvariable=self.key_var, width=40).grid(row=1, column=1, sticky="we", **pad)

        ttk.Label(settings, text="IV (hex, 16 bytes)").grid(row=2, column=0, sticky="w")
        self.iv_var = tk.StringVar(value=self.cfg.get("iv_hex", DEFAULT_IV_HEX))
        ttk.Entry(settings, textvariable=self.iv_var, width=40).grid(row=2, column=1, sticky="we", **pad)

        paths = ttk.LabelFrame(self, text="Paths")
        paths.pack(fill="x", **pad)

        ttk.Label(paths, text="Input .salakieli").grid(row=0, column=0, sticky="w")
        self.in_enc_var = tk.StringVar()
        ttk.Entry(paths, textvariable=self.in_enc_var, width=60).grid(row=0, column=1, sticky="we", **pad)
        ttk.Button(paths, text="Browse…", command=self.browse_in_enc).grid(row=0, column=2, **pad)

        ttk.Label(paths, text="Output plaintext").grid(row=1, column=0, sticky="w")
        self.out_plain_var = tk.StringVar()
        ttk.Entry(paths, textvariable=self.out_plain_var, width=60).grid(row=1, column=1, sticky="we", **pad)
        ttk.Button(paths, text="Save as…", command=self.choose_out_plain).grid(row=1, column=2, **pad)

        ttk.Label(paths, text="Input plaintext").grid(row=2, column=0, sticky="w")
        self.in_plain_var = tk.StringVar()
        ttk.Entry(paths, textvariable=self.in_plain_var, width=60).grid(row=2, column=1, sticky="we", **pad)
        ttk.Button(paths, text="Browse…", command=self.browse_in_plain).grid(row=2, column=2, **pad)

        ttk.Label(paths, text="Output .salakieli").grid(row=3, column=0, sticky="w")
        self.out_enc_var = tk.StringVar()
        ttk.Entry(paths, textvariable=self.out_enc_var, width=60).grid(row=3, column=1, sticky="we", **pad)
        ttk.Button(paths, text="Save as…", command=self.choose_out_enc).grid(row=3, column=2, **pad)

        actions = ttk.Frame(self)
        actions.pack(fill="x", **pad)
        self.dec_btn = ttk.Button(actions, text="⬇ Decrypt (.salakieli → editor + file)", command=self.on_decrypt)
        self.dec_btn.pack(side="left", padx=6)
        self.enc_btn = ttk.Button(actions, text="⬆ Encrypt (editor/plaintext → .salakieli)", command=self.on_encrypt)
        self.enc_btn.pack(side="left", padx=6)
        ttk.Button(actions, text="Check OpenSSL", command=self.check_openssl).pack(side="left", padx=12)

        editor_frame = ttk.LabelFrame(self, text="Editor (UTF‑8). You can edit then save or encrypt from here")
        editor_frame.pack(fill="both", expand=True, **pad)
        self.editor = ScrolledText(editor_frame, wrap="word", height=18)
        self.editor.pack(fill="both", expand=True, padx=6, pady=6)

        ed_actions = ttk.Frame(self)
        ed_actions.pack(fill="x", **pad)
        ttk.Button(ed_actions, text="Load plaintext into editor…", command=self.load_plain_into_editor).pack(side="left", padx=6)
        ttk.Button(ed_actions, text="Save editor to plaintext…", command=self.save_editor_to_plain).pack(side="left", padx=6)

        self.status = ttk.Label(self, text="Ready", anchor="w")
        self.status.pack(fill="x", padx=8, pady=(0,8))

        for f in (settings, paths):
            f.grid_columnconfigure(1, weight=1)

    def browse_openssl(self):
        path = filedialog.askopenfilename(title="Select openssl executable")
        if path:
            self.openssl_var.set(path)
            self._save_cfg()

    def browse_in_enc(self):
        path = filedialog.askopenfilename(title="Choose input .salakieli", filetypes=[("salakieli","*.salakieli"), ("All files","*.*")])
        if path:
            self.in_enc_var.set(path)

    def choose_out_plain(self):
        path = filedialog.asksaveasfilename(title="Choose output plaintext", defaultextension=".txt",
                                            filetypes=[("Text","*.txt"), ("All files","*.*")])
        if path:
            self.out_plain_var.set(path)

    def browse_in_plain(self):
        path = filedialog.askopenfilename(title="Choose input plaintext", filetypes=[("Text","*.txt"), ("All files","*.*")])
        if path:
            self.in_plain_var.set(path)

    def choose_out_enc(self):
        path = filedialog.asksaveasfilename(title="Choose output .salakieli", defaultextension=".salakieli",
                                            filetypes=[("salakieli","*.salakieli"), ("All files","*.*")])
        if path:
            self.out_enc_var.set(path)

    def check_openssl(self):
        exe = self._which(self.openssl_var.get().strip() or "openssl")
        try:
            p = subprocess.run([exe, "version", "-a"], capture_output=True, text=True, shell=False, timeout=5)
            if p.returncode == 0:
                out = p.stdout.strip() or p.stderr.strip()
                messagebox.showinfo("OpenSSL", out)
            else:
                messagebox.showerror("OpenSSL", p.stderr or f"Exit code {p.returncode}")
        except FileNotFoundError:
            messagebox.showerror("OpenSSL", f"Couldn't find openssl executable:\n{exe}\n\nInstall it or browse to it.")
        except Exception as e:
            messagebox.showerror("OpenSSL", str(e))

    def _save_cfg(self):
        cfg = {
            "openssl": self.openssl_var.get().strip(),
            "key_hex": self.key_var.get().strip(),
            "iv_hex": self.iv_var.get().strip(),
        }
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
        except Exception:
            pass

    def _validate_key_iv(self):
        key_hex = self.key_var.get().strip()
        iv_hex  = self.iv_var.get().strip()
        self._validate_hex_len("Key", key_hex, 32)
        self._validate_hex_len("IV",  iv_hex, 32)
        return key_hex, iv_hex

    @staticmethod
    def _validate_hex_len(name: str, s: str, want_len: int):
        if not s:
            raise ValueError(f"{name} is empty")
        try:
            int(s, 16)
        except ValueError:
            raise ValueError(f"{name} must be hex (0-9a-f)")
        if len(s) != want_len:
            raise ValueError(f"{name} must be {want_len} hex chars ({want_len//2} bytes)")

    @staticmethod
    def _which(program: str) -> str:
        if os.path.isfile(program):
            return program
        for p in os.environ.get("PATH", "").split(os.pathsep):
            candidate = os.path.join(p, program)
            if os.path.isfile(candidate):
                return candidate
            if os.name == "nt":
                candidate_exe = candidate + ".exe"
                if os.path.isfile(candidate_exe):
                    return candidate_exe
        return program

    def on_decrypt(self):
        self._save_cfg()
        try:
            key_hex, iv_hex = self._validate_key_iv()
            in_path  = self.in_enc_var.get().strip()
            out_path = self.out_plain_var.get().strip()
            if not in_path:
                raise ValueError("Choose an input .salakieli file")
            if not os.path.isfile(in_path):
                raise ValueError(f"Input not found:\n{in_path}")
            if not out_path:
                out_path = filedialog.asksaveasfilename(title="Where to save plaintext", defaultextension=".txt")
                if not out_path:
                    return
                self.out_plain_var.set(out_path)

            exe = self._which(self.openssl_var.get().strip() or "openssl")
            cmd = [exe, "enc", "-d", "-aes-128-ctr", "-in", in_path, "-K", key_hex, "-iv", iv_hex, "-out", out_path, "-nopad"]
            p = subprocess.run(cmd, capture_output=True, shell=False)
            if p.returncode != 0:
                raise RuntimeError(p.stderr.decode(errors="replace") or f"OpenSSL failed (exit {p.returncode})")

            try:
                with open(out_path, "rb") as f:
                    data = f.read()
                self.editor.delete("1.0", "end")
                self.editor.insert("1.0", data.decode("utf-8", errors="replace"))
            except Exception as e:
                self.editor.delete("1.0", "end")
                self.editor.insert("1.0", f"[Could not display as UTF-8; file saved to disk]\n{e}")

            self.status.config(text=f"Decrypted → {out_path}")
        except Exception as e:
            messagebox.showerror("Decrypt error", str(e))
            self.status.config(text="Decrypt failed")

    def on_encrypt(self):
        self._save_cfg()
        try:
            key_hex, iv_hex = self._validate_key_iv()
            in_plain = self.in_plain_var.get().strip()
            out_enc  = self.out_enc_var.get().strip()

            use_editor = False
            if not in_plain:
                use_editor = True

            if not out_enc:
                out_enc = filedialog.asksaveasfilename(title="Where to save .salakieli",
                                                       defaultextension=".salakieli",
                                                       filetypes=[("salakieli","*.salakieli"),("All files","*.*")])
                if not out_enc:
                    return
                self.out_enc_var.set(out_enc)

            exe = self._which(self.openssl_var.get().strip() or "openssl")

            if use_editor:
                text = self.editor.get("1.0", "end")
                with tempfile.NamedTemporaryFile(delete=False) as tf:
                    tf.write(text.encode("utf-8"))
                    tmp_in = tf.name
                try:
                    cmd = [exe, "enc", "-aes-128-ctr", "-in", tmp_in, "-K", key_hex, "-iv", iv_hex, "-out", out_enc, "-nopad"]
                    p = subprocess.run(cmd, capture_output=True, shell=False)
                finally:
                    try: os.remove(tmp_in)
                    except Exception: pass
            else:
                if not os.path.isfile(in_plain):
                    raise ValueError(f"Plaintext input not found:\n{in_plain}")
                cmd = [exe, "enc", "-aes-128-ctr", "-in", in_plain, "-K", key_hex, "-iv", iv_hex, "-out", out_enc, "-nopad"]
                p = subprocess.run(cmd, capture_output=True, shell=False)

            if p.returncode != 0:
                raise RuntimeError(p.stderr.decode(errors="replace") or f"OpenSSL failed (exit {p.returncode})")

            self.status.config(text=f"Encrypted → {out_enc}")
            messagebox.showinfo("Done", f"Saved {out_enc}")
        except Exception as e:
            messagebox.showerror("Encrypt error", str(e))
            self.status.config(text="Encrypt failed")

    def load_plain_into_editor(self):
        path = filedialog.askopenfilename(title="Load plaintext into editor", filetypes=[("Text","*.txt"),("All files","*.*")])
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
            self.editor.delete("1.0", "end")
            self.editor.insert("1.0", data.decode("utf-8", errors="replace"))
            self.in_plain_var.set(path)
            self.status.config(text=f"Loaded {path} into editor")
        except Exception as e:
            messagebox.showerror("Load error", str(e))

    def save_editor_to_plain(self):
        path = filedialog.asksaveasfilename(title="Save editor to plaintext", defaultextension=".txt",
                                            filetypes=[("Text","*.txt"),("All files","*.*")])
        if not path:
            return
        try:
            text = self.editor.get("1.0", "end")
            with open(path, "wb") as f:
                f.write(text.encode("utf-8"))
            self.out_plain_var.set(path)
            self.status.config(text=f"Saved editor → {path}")
        except Exception as e:
            messagebox.showerror("Save error", str(e))

if __name__ == "__main__":
    App().mainloop()
