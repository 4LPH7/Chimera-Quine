#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
chimera_gui_live.py
All-in-one GUI for building and inspecting "Chimera Quine" layers with a LIVE header.
Each layer_X.dat is a polyglot:
  [ Python quine + /key HTTP server + fractal HTML ] + "__ZIP_START__\n" + [ zip or AES-GCM(zip) ]

Features:
- Build chained layers (depth, basename, outdir), optional AES-GCM encryption (key = sha256(header))
- Progress bar and live log output
- Fractal visualizer (Mandelbrot) inside the GUI (zoom/pan, optional PNG export with pillow)
- Key inspector (compute SHA-256 of header)
- Decryptor (auto-derive key from header or manual, decrypt payload to ZIP, optional unzip)
- JSON config export/import and appearance mode toggle
"""

import os
import io
import sys
import json
import math
import time
import queue
import hashlib
import zipfile
import tempfile
import traceback
from pathlib import Path
from threading import Thread

import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

# Optional: cryptography and PNG export
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False

try:
    from PIL import Image
    HAVE_PIL = True
except Exception:
    HAVE_PIL = False

APP_TITLE = "🧬 Chimera Builder Live"
MARKER = b"__ZIP_START__\n"

# ===========================================================
# Utility Helpers
# ===========================================================

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def derive_key_from_header(header: bytes) -> bytes:
    return bytes.fromhex(sha256_bytes(header))

def aes_gcm_encrypt(raw_bytes: bytes, key_bytes: bytes) -> bytes:
    if not HAVE_CRYPTO:
        raise RuntimeError("pycryptodome not installed. pip install pycryptodome")
    from Crypto.Cipher import AES  # local import for safety
    from Crypto.Random import get_random_bytes
    nonce = get_random_bytes(12)
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(raw_bytes)
    return nonce + tag + ct

def aes_gcm_decrypt(enc_bytes: bytes, key_bytes: bytes) -> bytes:
    if not HAVE_CRYPTO:
        raise RuntimeError("pycryptodome not installed. pip install pycryptodome")
    if len(enc_bytes) < 12 + 16:
        raise ValueError("Encrypted blob too small to contain nonce/tag")
    nonce = enc_bytes[:12]
    tag = enc_bytes[12:28]
    ct = enc_bytes[28:]
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

def read_header_bytes(path: Path) -> bytes:
    data = Path(path).read_bytes()
    idx = data.find(MARKER)
    return data if idx == -1 else data[:idx]

def read_payload_bytes(path: Path) -> bytes:
    data = Path(path).read_bytes()
    idx = data.find(MARKER)
    if idx == -1:
        return b""
    return data[idx + len(MARKER):]

def make_zip_from_map(file_map: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arcname, content in file_map.items():
            if isinstance(content, (bytes, bytearray)):
                zf.writestr(arcname, content)
            else:
                zf.writestr(arcname, str(content))
    return buf.getvalue()

# ===========================================================
# LIVE Python Header (executed inside each layer when run)
# ===========================================================

# The header is designed to be safe to embed; it starts a minimal HTTP server that serves:
#   /        -> fractal visualizer (client-side canvas)
#   /key     -> the sha256(header) key
# It prints its own header (quine-like face) and the key on stdout, then runs the server.

LIVE_HEADER = r'''#!/usr/bin/env python3
# Chimera Layer {layer_no} - LIVE header
# Acts as a quine-like Python face + /key server + fractal visualizer.
import os, sys, hashlib, threading
from http.server import HTTPServer, BaseHTTPRequestHandler

_MARKER = b"__ZIP_START__\n"

def read_own_header():
    p = os.path.abspath(__file__)
    with open(p, "rb") as f:
        data = f.read()
    i = data.find(_MARKER)
    return data if i == -1 else data[:i]

def layer_key_hex():
    return hashlib.sha256(read_own_header()).hexdigest()

# Embedded fractal HTML/JS (compact, no deps)
FRACTAL_HTML = """<!doctype html><html><head><meta charset='utf-8'><title>Chimera Fractal</title>
<style>html,body{height:100%;margin:0;background:#000}canvas{width:100%;height:100%;display:block}</style></head>
<body><canvas id=c></canvas><script>
const C=document.getElementById('c'),X=C.getContext('2d');let W,H;function R(){C.width=W=innerWidth;C.height=H=innerHeight;D()}addEventListener('resize',R);
let cx=-0.6,cy=0,scale=3;let drag=0,lx=0,ly=0;
C.addEventListener('mousedown',e=>{drag=1;lx=e.clientX;ly=e.clientY});addEventListener('mouseup',()=>drag=0);
addEventListener('mousemove',e=>{if(!drag)return;const dx=(e.clientX-lx)/W*scale,dy=(e.clientY-ly)/H*scale;cx-=dx;cy-=dy;lx=e.clientX;ly=e.clientY;D();});
addEventListener('wheel',e=>{e.preventDefault();const k=e.deltaY>0?1.12:0.88;const mx=(e.clientX/W-0.5)*scale,my=(e.clientY/H-0.5)*scale;cx+=mx*(1-1/k);cy+=my*(1-1/k);scale*=k;D();},{passive:false});
function D(){const I=X.createImageData(W,H);const M=Math.max(100,Math.floor(220-Math.log10(scale+1)*40));
for(let y=0;y<H;y++){{for(let x=0;x<W;x++){let x0=(x/W-0.5)*scale+cx,y0=(y/H-0.5)*scale+cy,xr=0,yi=0,i=0;while(xr*xr+yi*yi<=4&&i<M){const t=xr*xr-yi*yi+x0;yi=2*xr*yi+y0;xr=t;i++;}const p=(y*W+x)*4,tv=i/M;I.data[p]=Math.floor(255*tv*tv);I.data[p+1]=Math.floor(255*(1-tv)*tv);I.data[p+2]=Math.floor(255*(1-tv));I.data[p+3]=255;}}}
X.putImageData(I,0,0);X.fillStyle='rgba(0,0,0,0.4)';X.fillRect(6,6,260,34);X.fillStyle='#fff';X.font='12px monospace';X.fillText('center: '+cx.toFixed(6)+', '+cy.toFixed(6),12,22);X.fillText('scale: '+scale.toExponential(3),12,36);}
R();</script></body></html>"""

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = FRACTAL_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body); return
        if self.path == "/key":
            key = layer_key_hex().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type","text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(key)))
            self.end_headers()
            self.wfile.write(key); return
        self.send_response(404); self.end_headers()

def run_server():
    addr=("127.0.0.1", 8000)
    httpd=HTTPServer(addr, Handler)
    print(f"Serving fractal at http://{addr[0]}:{addr[1]}/  (key at /key)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()

def main():
    hdr = read_own_header()
    try:
        print(hdr.decode("utf-8", errors="replace"))
    except Exception:
        print("(binary header)")
    k = layer_key_hex()
    print("\\n--- LAYER KEY (sha256(header)) ---")
    print(k)
    print("-----------------------------------\\n")
    run_server()

if __name__=="__main__":
    main()

# MARKER: Python ignores bytes after this line; unzip looks from the end.
__ZIP_START__
'''

def build_live_header(layer_no: int) -> bytes:
    return LIVE_HEADER.format(layer_no=layer_no).encode("utf-8")

# ===========================================================
# Builder Engine
# ===========================================================

class ChimeraBuilder:
    def __init__(self, out_dir: Path, depth: int, encrypt: bool, basename="layer",
                 progress_cb=None, log_cb=None):
        self.out_dir = Path(out_dir)
        self.depth = int(depth)
        self.encrypt = bool(encrypt)
        self.basename = basename
        self.progress_cb = progress_cb or (lambda v: None)
        self.log_cb = log_cb or (lambda s: None)
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def _log(self, msg: str):
        self.log_cb(msg)

    def _progress(self, frac: float):
        self.progress_cb(max(0.0, min(1.0, frac)))

    def _write_layer(self, layer_no: int, payload: bytes) -> Path:
        header = build_live_header(layer_no)
        out = self.out_dir / f"{self.basename}_{layer_no}.dat"
        out.write_bytes(header + MARKER + payload)
        self._log(f"[+] Wrote {out.name} ({out.stat().st_size} bytes)")
        return out

    def build(self):
        if self.depth < 1:
            raise ValueError("Depth must be >= 1")
        total_steps = self.depth
        step_i = 0

        # Base (final) layer: contains a tiny ZIP with a final README.
        base_zip = make_zip_from_map({"README.txt": "Final layer. You’ve reached the end.\n"})
        self._write_layer(self.depth, base_zip)
        step_i += 1
        self._progress(step_i / total_steps)

        # Wrap upwards: i = depth-1 down to 1
        for i in range(self.depth - 1, 0, -1):
            child_name = f"{self.basename}_{i+1}.dat"
            child_bytes = (self.out_dir / child_name).read_bytes()
            readme = (
                f"Chimera layer {i}\n"
                f"Contains next: {child_name}\n"
                f"- Run: python {self.basename}_{i}.dat\n"
                f"- Visit /key at http://127.0.0.1:8000 for the key (sha256(header)).\n"
                f"If payload is encrypted, use this key to decrypt the appended blob.\n"
            )
            zip_bytes = make_zip_from_map({"README.txt": readme, child_name: child_bytes})

            header_i = build_live_header(i)
            if self.encrypt:
                if not HAVE_CRYPTO:
                    raise RuntimeError("pycryptodome is required for encryption. pip install pycryptodome")
                key = derive_key_from_header(header_i)
                zip_bytes = aes_gcm_encrypt(zip_bytes, key)
                self._log(f"[enc] Layer {i} payload encrypted (AES-GCM; key=sha256(header))")

            self._write_layer(i, zip_bytes)
            step_i += 1
            self._progress(step_i / total_steps)

        self._log("✅ Build complete.")

# ===========================================================
# Fractal Renderer (in-GUI)
# ===========================================================

class FractalCanvas(ctk.CTkCanvas):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.configure(highlightthickness=0, bg="black")
        self.bind("<Configure>", self._on_resize)
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<B1-Motion>", self._on_drag)
        self.bind("<MouseWheel>", self._on_wheel)     # Windows
        self.bind("<Button-4>", self._on_wheel_linux) # Linux up
        self.bind("<Button-5>", self._on_wheel_linux) # Linux down

        self.dragging = False
        self.last_pos = (0, 0)
        self.cx, self.cy, self.scale = -0.6, 0.0, 3.0
        self.img = None
        self._rendering = False
        self.after(60, self.render)

    def _on_resize(self, _):
        self.render()

    def _on_press(self, e):
        self.dragging = True
        self.last_pos = (e.x, e.y)

    def _on_drag(self, e):
        if not self.dragging:
            return
        w = max(1, self.winfo_width())
        h = max(1, self.winfo_height())
        dx = (e.x - self.last_pos[0]) / w * self.scale
        dy = (e.y - self.last_pos[1]) / h * self.scale
        self.cx -= dx
        self.cy -= dy
        self.last_pos = (e.x, e.y)
        self.render()

    def _on_wheel(self, e):
        k = 0.88 if e.delta > 0 else 1.12
        self._zoom_at(e.x, e.y, k)

    def _on_wheel_linux(self, e):
        k = 0.88 if e.num == 4 else 1.12
        self._zoom_at(e.x, e.y, k)

    def _zoom_at(self, x, y, k):
        w = max(1, self.winfo_width())
        h = max(1, self.winfo_height())
        mx = (x / w - 0.5) * self.scale
        my = (y / h - 0.5) * self.scale
        self.cx += mx * (1 - 1/k)
        self.cy += my * (1 - 1/k)
        self.scale *= k
        self.render()

    def render(self):
        if self._rendering:
            return
        self._rendering = True

        def work():
            try:
                w = max(1, self.winfo_width())
                h = max(1, self.winfo_height())
                max_iter = max(100, int(220 - math.log10(self.scale + 1) * 40))
                img = tk.PhotoImage(width=w, height=h)
                for py in range(h):
                    row = []
                    for px in range(w):
                        x0 = (px / w - 0.5) * self.scale + self.cx
                        y0 = (py / h - 0.5) * self.scale + self.cy
                        x = y = 0.0
                        it = 0
                        while x*x + y*y <= 4.0 and it < max_iter:
                            x, y = x*x - y*y + x0, 2*x*y + y0
                            it += 1
                        t = it / max_iter
                        r = int(255 * t * t)
                        g = int(255 * (1 - t) * t)
                        b = int(255 * (1 - t))
                        row.append(f"#{r:02x}{g:02x}{b:02x}")
                    img.put(" ".join(row), to=(0, py))
                self.after(0, self._set_image, img)
            finally:
                self._rendering = False

        Thread(target=work, daemon=True).start()

    def _set_image(self, img):
        self.img = img
        self.delete("all")
        self.create_image(0, 0, image=self.img, anchor="nw")
        self._overlay()

    def _overlay(self):
        self.create_rectangle(8, 8, 300, 48, fill="#00000066", width=0)
        text = f"center=({self.cx:.6f}, {self.cy:.6f})  scale={self.scale:.4e}"
        self.create_text(16, 16, text=text, anchor="nw", fill="white", font=("Consolas", 10, "normal"))

# ===========================================================
# GUI Application
# ===========================================================

class ChimeraApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1040x720")
        ctk.set_appearance_mode("system")
        ctk.set_default_color_theme("dark-blue")
        self._build_ui()

    def _build_ui(self):
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(self)
        top.grid(row=0, column=0, sticky="ew", padx=10, pady=8)
        ctk.CTkLabel(top, text=APP_TITLE, font=("Segoe UI", 22, "bold")).pack(side="left", padx=8)
        self.appearance = ctk.CTkOptionMenu(top, values=["System", "Dark", "Light"], command=self._on_appearance)
        self.appearance.set("System")
        self.appearance.pack(side="right", padx=6)

        tabs = ctk.CTkTabview(self)
        tabs.grid(row=1, column=0, sticky="nsew", padx=10, pady=8)

        self.tab_build = tabs.add("Build")
        self.tab_visual = tabs.add("Fractal Visualizer")
        self.tab_keys = tabs.add("Key Inspector")
        self.tab_decrypt = tabs.add("Decryptor")
        self.tab_config = tabs.add("Config")

        self._build_tab_build()
        self._build_tab_visual()
        self._build_tab_keys()
        self._build_tab_decrypt()
        self._build_tab_config()

    # ---------------- Build tab ----------------
    def _build_tab_build(self):
        frm = self.tab_build
        frm.grid_rowconfigure(5, weight=1)
        frm.grid_columnconfigure(1, weight=1)

        self.var_depth = tk.IntVar(value=3)
        self.var_encrypt = tk.BooleanVar(value=True)
        self.var_basename = tk.StringVar(value="layer")
        self.var_outdir = tk.StringVar(value=os.path.abspath("chimera_output"))

        ctk.CTkLabel(frm, text="Depth:").grid(row=0, column=0, sticky="e", padx=6, pady=6)
        ctk.CTkEntry(frm, textvariable=self.var_depth, width=80).grid(row=0, column=1, sticky="w", pady=6)

        ctk.CTkLabel(frm, text="Base name:").grid(row=1, column=0, sticky="e", padx=6, pady=6)
        ctk.CTkEntry(frm, textvariable=self.var_basename, width=160).grid(row=1, column=1, sticky="w", pady=6)

        ctk.CTkLabel(frm, text="Output directory:").grid(row=2, column=0, sticky="e", padx=6, pady=6)
        ctk.CTkEntry(frm, textvariable=self.var_outdir).grid(row=2, column=1, sticky="ew", pady=6)
        ctk.CTkButton(frm, text="Browse", command=self._choose_outdir).grid(row=2, column=2, padx=6)

        ctk.CTkCheckBox(frm, text="Encrypt inner zips (AES-GCM; key = sha256(header))",
                        variable=self.var_encrypt).grid(row=3, column=1, sticky="w", padx=2, pady=4)

        bar = ctk.CTkFrame(frm)
        bar.grid(row=4, column=0, columnspan=3, sticky="ew", pady=8)
        ctk.CTkButton(bar, text="Build Chain", height=40, command=self._start_build).pack(side="left", padx=6)
        ctk.CTkButton(bar, text="Open Output", command=self._open_outdir).pack(side="left", padx=6)

        self.prog = ctk.CTkProgressBar(frm)
        self.prog.set(0.0)
        self.prog.grid(row=5, column=0, columnspan=3, sticky="ew", padx=6, pady=(2,6))

        self.log = ctk.CTkTextbox(frm, height=260)
        self.log.grid(row=6, column=0, columnspan=3, sticky="nsew", padx=6, pady=6)

    def _choose_outdir(self):
        d = filedialog.askdirectory()
        if d:
            self.var_outdir.set(d)

    def _open_outdir(self):
        p = Path(self.var_outdir.get())
        p.mkdir(parents=True, exist_ok=True)
        if sys.platform.startswith("win"):
            os.startfile(p)  # noqa
        elif sys.platform == "darwin":
            os.system(f'open "{p}"')
        else:
            os.system(f'xdg-open "{p}"')

    def _start_build(self):
        outdir = Path(self.var_outdir.get())
        depth = self.var_depth.get()
        encrypt = self.var_encrypt.get()
        basename = self.var_basename.get()

        if encrypt and not HAVE_CRYPTO:
            messagebox.showwarning("Crypto missing", "pycryptodome not installed.\nRun: pip install pycryptodome")
            return

        self._log_clear()
        self._log(f"Building chain: depth={depth}, encrypt={encrypt}, base={basename}")
        self.prog.set(0.0)

        def log_cb(s):
            self._log(s)

        def prog_cb(frac):
            self.prog.set(frac)

        def job():
            try:
                ChimeraBuilder(outdir, depth, encrypt, basename, prog_cb, log_cb).build()
            except Exception as e:
                self._log("ERROR: " + str(e))
                self._log(traceback.format_exc())

        Thread(target=job, daemon=True).start()

    def _log(self, text):
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.update_idletasks()

    def _log_clear(self):
        self.log.delete("1.0", "end")

    # ---------------- Fractal Visualizer tab ----------------
    def _build_tab_visual(self):
        frm = self.tab_visual
        frm.grid_rowconfigure(0, weight=1)
        frm.grid_columnconfigure(0, weight=1)

        self.fractal = FractalCanvas(frm)
        self.fractal.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)

        bar = ctk.CTkFrame(frm)
        bar.grid(row=1, column=0, sticky="ew", padx=6, pady=(0,6))
        ctk.CTkButton(bar, text="Reset View", command=self._reset_fractal).pack(side="left", padx=6)
        ctk.CTkButton(bar, text="Save PNG", command=self._save_fractal_png).pack(side="left", padx=6)

    def _reset_fractal(self):
        self.fractal.cx, self.fractal.cy, self.fractal.scale = -0.6, 0.0, 3.0
        self.fractal.render()

    def _save_fractal_png(self):
        if not HAVE_PIL:
            messagebox.showwarning("PNG export", "Install pillow: pip install pillow")
            return
        path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG", "*.png")])
        if not path:
            return
        # Render via PIL to the chosen size (current canvas size)
        w = max(1, self.fractal.winfo_width())
        h = max(1, self.fractal.winfo_height())
        img = Image.new("RGB", (w, h))
        px = img.load()
        max_iter = max(100, int(220 - math.log10(self.fractal.scale + 1) * 40))
        for py in range(h):
            for px_i in range(w):
                x0 = (px_i / w - 0.5) * self.fractal.scale + self.fractal.cx
                y0 = (py / h - 0.5) * self.fractal.scale + self.fractal.cy
                x = y = 0.0
                it = 0
                while x*x + y*y <= 4.0 and it < max_iter:
                    x, y = x*x - y*y + x0, 2*x*y + y0
                    it += 1
                t = it / max_iter
                r = int(255 * t * t)
                g = int(255 * (1 - t) * t)
                b = int(255 * (1 - t))
                px[px_i, py] = (r, g, b)
        img.save(path, "PNG")
        messagebox.showinfo("Saved", f"Saved fractal to:\n{path}")

    # ---------------- Key Inspector tab ----------------
    def _build_tab_keys(self):
        frm = self.tab_keys
        frm.grid_columnconfigure(1, weight=1)

        self.var_key_file = tk.StringVar(value="")
        ctk.CTkLabel(frm, text="Layer file (.dat):").grid(row=0, column=0, sticky="e", padx=6, pady=6)
        ctk.CTkEntry(frm, textvariable=self.var_key_file).grid(row=0, column=1, sticky="ew", padx=6, pady=6)
        ctk.CTkButton(frm, text="Browse", command=self._pick_key_file).grid(row=0, column=2, padx=6)

        ctk.CTkButton(frm, text="Compute Key", command=self._compute_key).grid(row=1, column=0, padx=6, pady=6)
        self.key_out = ctk.CTkEntry(frm)
        self.key_out.grid(row=1, column=1, sticky="ew", padx=6, pady=6)
        ctk.CTkButton(frm, text="Copy", command=self._copy_key).grid(row=1, column=2, padx=6)

    def _pick_key_file(self):
        p = filedialog.askopenfilename(filetypes=[("Chimera layer", "*.dat"), ("All files", "*.*")])
        if p:
            self.var_key_file.set(p)

    def _compute_key(self):
        try:
            hdr = read_header_bytes(Path(self.var_key_file.get()))
            key_hex = sha256_bytes(hdr)
            self.key_out.delete(0, "end")
            self.key_out.insert(0, key_hex)
        except Exception as e:
            messagebox.showerror("Key error", str(e))

    def _copy_key(self):
        k = self.key_out.get()
        if not k:
            return
        self.clipboard_clear()
        self.clipboard_append(k)
        self.update()
        messagebox.showinfo("Copied", "Key copied to clipboard.")

    # ---------------- Decryptor tab ----------------
    def _build_tab_decrypt(self):
        frm = self.tab_decrypt
        frm.grid_columnconfigure(1, weight=1)

        self.var_dec_file = tk.StringVar(value="")
        self.var_dec_outzip = tk.StringVar(value=os.path.abspath("decrypted_payload.zip"))
        self.var_dec_unzip = tk.BooleanVar(value=True)
        self.var_dec_outdir = tk.StringVar(value=os.path.abspath("decrypted_output"))

        ctk.CTkLabel(frm, text="Layer file (.dat):").grid(row=0, column=0, sticky="e", padx=6, pady=6)
        ctk.CTkEntry(frm, textvariable=self.var_dec_file).grid(row=0, column=1, sticky="ew", padx=6, pady=6)
        ctk.CTkButton(frm, text="Browse", command=self._pick_dec_file).grid(row=0, column=2, padx=6)

        ctk.CTkLabel(frm, text="Key (hex) [leave blank = auto derive from header]:").grid(row=1, column=0, sticky="e", padx=6, pady=6)
        self.dec_key_entry = ctk.CTkEntry(frm)
        self.dec_key_entry.grid(row=1, column=1, sticky="ew", padx=6, pady=6)

        ctk.CTkLabel(frm, text="Save decrypted ZIP to:").grid(row=2, column=0, sticky="e", padx=6, pady=6)
        ctk.CTkEntry(frm, textvariable=self.var_dec_outzip).grid(row=2, column=1, sticky="ew", padx=6, pady=6)
        ctk.CTkButton(frm, text="Browse", command=self._pick_outzip).grid(row=2, column=2, padx=6)

        ctk.CTkCheckBox(frm, text="Unzip after decrypt", variable=self.var_dec_unzip).grid(row=3, column=1, sticky="w")

        ctk.CTkLabel(frm, text="Unzip to directory:").grid(row=4, column=0, sticky="e", padx=6, pady=6)
        ctk.CTkEntry(frm, textvariable=self.var_dec_outdir).grid(row=4, column=1, sticky="ew", padx=6, pady=6)
        ctk.CTkButton(frm, text="Browse", command=self._pick_outdir).grid(row=4, column=2, padx=6)

        ctk.CTkButton(frm, text="Decrypt (and Unzip)", height=40, command=self._start_decrypt).grid(row=5, column=1, pady=12)

        self.dec_log = ctk.CTkTextbox(frm, height=240)
        self.dec_log.grid(row=6, column=0, columnspan=3, sticky="nsew", padx=6, pady=6)

    def _pick_dec_file(self):
        p = filedialog.askopenfilename(filetypes=[("Chimera layer", "*.dat"), ("All files", "*.*")])
        if p:
            self.var_dec_file.set(p)

    def _pick_outzip(self):
        p = filedialog.asksaveasfilename(defaultextension=".zip", filetypes=[("ZIP", "*.zip")])
        if p:
            self.var_dec_outzip.set(p)

    def _pick_outdir(self):
        d = filedialog.askdirectory()
        if d:
            self.var_dec_outdir.set(d)

    def _start_decrypt(self):
        path = Path(self.var_dec_file.get())
        if not path.exists():
            messagebox.showerror("Decrypt", "Select a valid layer file (.dat)")
            return
        key_hex = self.dec_key_entry.get().strip()
        auto = False
        if not key_hex:
            hdr = read_header_bytes(path)
            key_hex = sha256_bytes(hdr)
            auto = True
        try:
            key_bytes = bytes.fromhex(key_hex)
        except ValueError:
            messagebox.showerror("Decrypt", "Key must be a valid hex string.")
            return

        outzip = Path(self.var_dec_outzip.get())
        outdir = Path(self.var_dec_outdir.get())
        do_unzip = self.var_dec_unzip.get()

        self._dec_log_clear()
        self._dec_log(f"Decrypting: {path.name}")
        if auto:
            self._dec_log("(Auto-derived key from header)")

        def job():
            try:
                payload = read_payload_bytes(path)
                # Try decrypt; if fails, assume payload is plain ZIP
                try:
                    zip_bytes = aes_gcm_decrypt(payload, key_bytes)
                    self._dec_log("[+] AES-GCM decryption successful.")
                except Exception:
                    self._dec_log("[i] Decryption failed or not encrypted; assuming plain ZIP.")
                    zip_bytes = payload

                outzip.parent.mkdir(parents=True, exist_ok=True)
                outzip.write_bytes(zip_bytes)
                self._dec_log(f"[+] Saved ZIP: {outzip}")

                if do_unzip:
                    outdir.mkdir(parents=True, exist_ok=True)
                    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                        zf.extractall(outdir)
                    self._dec_log(f"[+] Unzipped to: {outdir.resolve()}")
                self._dec_log("✅ Done.")
            except Exception as e:
                self._dec_log("ERROR: " + str(e))
                self._dec_log(traceback.format_exc())

        Thread(target=job, daemon=True).start()

    def _dec_log(self, s: str):
        self.dec_log.insert("end", s + "\n")
        self.dec_log.see("end")
        self.update_idletasks()

    def _dec_log_clear(self):
        self.dec_log.delete("1.0", "end")

    # ---------------- Config tab ----------------
    def _build_tab_config(self):
        frm = self.tab_config
        frm.grid_columnconfigure(1, weight=1)

        self.var_cfg_depth = tk.IntVar(value=3)
        self.var_cfg_encrypt = tk.BooleanVar(value=True)
        self.var_cfg_basename = tk.StringVar(value="layer")
        self.var_cfg_outdir = tk.StringVar(value=os.path.abspath("chimera_output"))

        def load_from_builder():
            self.var_cfg_depth.set(self.var_depth.get())
            self.var_cfg_encrypt.set(self.var_encrypt.get())
            self.var_cfg_basename.set(self.var_basename.get())
            self.var_cfg_outdir.set(self.var_outdir.get())

        def apply_to_builder():
            self.var_depth.set(self.var_cfg_depth.get())
            self.var_encrypt.set(self.var_cfg_encrypt.get())
            self.var_basename.set(self.var_cfg_basename.get())
            self.var_outdir.set(self.var_cfg_outdir.get())
            messagebox.showinfo("Config", "Applied to Builder settings.")

        ctk.CTkButton(frm, text="Load Current Builder Settings", command=load_from_builder).grid(row=0, column=0, padx=6, pady=8)
        ctk.CTkButton(frm, text="Apply to Builder", command=apply_to_builder).grid(row=0, column=1, padx=6, pady=8, sticky="w")

        ctk.CTkLabel(frm, text="Depth:").grid(row=1, column=0, sticky="e", padx=6, pady=6)
        ctk.CTkEntry(frm, textvariable=self.var_cfg_depth).grid(row=1, column=1, sticky="w", padx=6, pady=6)

        ctk.CTkLabel(frm, text="Encrypt:").grid(row=2, column=0, sticky="e", padx=6, pady=6)
        ctk.CTkSwitch(frm, text="", variable=self.var_cfg_encrypt).grid(row=2, column=1, sticky="w", padx=6, pady=6)

        ctk.CTkLabel(frm, text="Basename:").grid(row=3, column=0, sticky="e", padx=6, pady=6)
        ctk.CTkEntry(frm, textvariable=self.var_cfg_basename).grid(row=3, column=1, sticky="w", padx=6, pady=6)

        ctk.CTkLabel(frm, text="Outdir:").grid(row=4, column=0, sticky="e", padx=6, pady=6)
        ctk.CTkEntry(frm, textvariable=self.var_cfg_outdir).grid(row=4, column=1, sticky="ew", padx=6, pady=6)
        ctk.CTkButton(frm, text="Browse", command=self._browse_cfg_outdir).grid(row=4, column=2, padx=6)

        bar = ctk.CTkFrame(frm)
        bar.grid(row=5, column=0, columnspan=3, sticky="ew", padx=6, pady=8)
        ctk.CTkButton(bar, text="Export Config (JSON)", command=self._export_config).pack(side="left", padx=6)
        ctk.CTkButton(bar, text="Import Config (JSON)", command=self._import_config).pack(side="left", padx=6)

        self.cfg_text = ctk.CTkTextbox(frm, height=260)
        self.cfg_text.grid(row=6, column=0, columnspan=3, sticky="nsew", padx=6, pady=6)

    def _browse_cfg_outdir(self):
        d = filedialog.askdirectory()
        if d:
            self.var_cfg_outdir.set(d)

    def _export_config(self):
        conf = {
            "depth": self.var_cfg_depth.get(),
            "encrypt": self.var_cfg_encrypt.get(),
            "basename": self.var_cfg_basename.get(),
            "outdir": self.var_cfg_outdir.get(),
        }
        s = json.dumps(conf, indent=2)
        self.cfg_text.delete("1.0", "end")
        self.cfg_text.insert("1.0", s)
        p = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")], title="Save Config")
        if p:
            Path(p).write_text(s, encoding="utf-8")
            messagebox.showinfo("Config", f"Saved: {p}")

    def _import_config(self):
        p = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if not p:
            return
        try:
            conf = json.loads(Path(p).read_text(encoding="utf-8"))
            self.var_cfg_depth.set(int(conf.get("depth", 3)))
            self.var_cfg_encrypt.set(bool(conf.get("encrypt", True)))
            self.var_cfg_basename.set(str(conf.get("basename", "layer")))
            self.var_cfg_outdir.set(str(conf.get("outdir", os.path.abspath("chimera_output"))))
            self.cfg_text.delete("1.0", "end")
            self.cfg_text.insert("1.0", json.dumps(conf, indent=2))
            messagebox.showinfo("Config", "Loaded.")
        except Exception as e:
            messagebox.showerror("Config", f"Failed to load: {e}")

    # ---------------- Appearance ----------------
    def _on_appearance(self, value: str):
        v = value.lower()
        if v == "dark":
            ctk.set_appearance_mode("dark")
        elif v == "light":
            ctk.set_appearance_mode("light")
        else:
            ctk.set_appearance_mode("system")

# ===========================================================
# Entry
# ===========================================================

if __name__ == "__main__":
    app = ChimeraApp()
    app.mainloop()
