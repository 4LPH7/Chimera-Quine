
# 🧬 Chimera Quine

**Chimera Builder Live** is an all-in-one graphical (GUI) tool for creating, inspecting, and decrypting "Chimera Quines."

A Chimera Quine is an advanced **polyglot file**. Each file (`layer_X.dat`) is simultaneously:

1.  A **Python Script** that prints its own source code and runs a web server.
2.  A **ZIP Archive** that contains the *next* layer in the recursive chain.

This tool allows you to build these recursive, steganographic files, which can be encrypted and obfuscated to create complex Capture The Flag (CTF) challenges or educational tools.

-----

## ✨ Features

  * **Recursive Builder:** Create chained polyglot files (`layer_1.dat` contains `layer_2.dat`, etc.) to any depth.
  * **Steganography:** Embed a custom file (like a photo, document, or binary) as the "treasure" in the final layer.
  * **AES-GCM Encryption:** Securely encrypt each layer's payload. The decryption key is automatically derived from the **SHA-256 hash of the Python header**, forcing the user to *have* the file to find the key.
  * **Header Obfuscation:** Optionally compress (zlib) and Base64-encode the Python header to hide its true purpose from casual inspection.
  * **File Inspector:** Load any `.dat` file to instantly see its header/payload size, SHA-256 hashes, and the derived decryption key.
  * **Integrated Decryptor:** A full-featured tool to decrypt and unzip any layer, either by auto-deriving the key or entering one manually.
  * **Live Test:** A "Run Top Layer" button to immediately execute your creation in a new console window.
  * **Fractal Visualizer:** An interactive Mandelbrot fractal visualizer is built into the GUI and also *served by the Python script* in each layer file.

-----

## 🚀 How to Use

### 📋 Requirements

Before running, you need to install the required Python libraries:

```sh
pip install customtkinter pycryptodome pillow
```

Save the script as `chimera_gui_live.py` and run it:

```sh
python chimera_gui_live.py
```

-----

### 1\. 🛠️ Build Tab

This is the main control panel for creating your file chain.

1.  **Depth:** How many layers to create. A depth of `3` creates `layer_1.dat`, `layer_2.dat`, and `layer_3.dat`.
2.  **Base name:** The prefix for your files (e.g., "layer").
3.  **Output directory:** Where the generated files will be saved.
4.  **Base Layer Type:**
      * **Default (README):** The final layer (`layer_3.dat`) will just contain a simple `README.txt`.
      * **Embed File:** Allows you to select *any file* from your computer to be the "treasure" hidden in the final layer.
5.  **Options:**
      * **Encrypt inner zips:** (Highly recommended) Encrypts the payload of each layer.
      * **Obfuscate Python header:** Makes the Python code unreadable at a glance, hiding the `LIVE_HEADER` logic.
6.  **Build Chain:** Click this to start the build process.
7.  **Run Top Layer:** After building, click this to test-run `layer_1.dat` immediately. This will open a new terminal, print the key for layer 2, and start the fractal web server.

### 2\. 🔎 File Inspector Tab

Use this to analyze any `.dat` file you've created or received.

1.  Click **"Browse"** and select a `layer_X.dat` file.
2.  Click **"Inspect File"**.
3.  The tool instantly shows you:
      * **Header Size:** The size of the Python script part.
      * **Payload Size:** The size of the ZIP/encrypted part.
      * **Header SHA-256:** The hash of the header.
      * **Derived Key:** The **decryption key** for this layer's payload (which is just the Header SHA-256). You can copy this key.

### 3\. 🔑 Decryptor Tab

This tab lets you "play" the CTF by manually decrypting each layer.

1.  **Layer file (.dat):** Select the file you want to decrypt (e.g., `layer_1.dat`).
2.  **Key (hex):**
      * **Leave blank (Auto):** The tool will automatically use the "File Inspector" logic to get the key from the header.
      * **Manual:** Paste in a key you found elsewhere.
3.  **Save decrypted ZIP to:** Choose a name for the output (e.g., `decrypted_layer_2.zip`).
4.  **Unzip after decrypt:** If checked, the tool will automatically unzip the decrypted ZIP file into the "Unzip to directory".
5.  Click **"Decrypt (and Unzip)"**.
6.  You can then inspect the unzipped files. The payload will be the *next* layer (e.g., `layer_2.dat`), which you can then load back into this tab to continue the chain.

-----

## 🎯 Applications & Use Cases

  * **CTF Development:** Create a "rabbit hole" style challenge where each layer must be executed to get the key, then decrypted to get the next file. The obfuscation and encryption features make this non-trivial.
  * **Steganography:** A novel way to hide a file. The final payload (your embedded file) is hidden inside a recursive, encrypted, and obfuscated file that just looks like a weird Python script.
  * **Educational Tool:** A fantastic, hands-on way to teach advanced concepts like:
      * **Polyglots:** How a file can be valid as multiple file types.
      * **Recursion:** A data structure that contains a version of itself.
      * **Steganography:** Hiding data in plain sight.
      * **Hashing:** Using a SHA-256 hash as a derived encryption key.
  * **Digital Art:** Can be seen as a form of generative art, a self-referential "data fractal" that is both code and container.
