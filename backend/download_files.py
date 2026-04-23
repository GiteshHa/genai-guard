import urllib.request
import os

# Save Tesseract files to extension folder
save_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'extension')
save_dir = os.path.normpath(save_dir)

if not os.path.exists(save_dir):
    os.makedirs(save_dir)

files = {
    "tesseract.min.js": "https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js",
    "worker.min.js": "https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/worker.min.js",
    "tesseract-core.wasm.js": "https://cdn.jsdelivr.net/npm/tesseract.js-core@5/tesseract-core.wasm.js"
}

print("🔽 Downloading Tesseract OCR files into extension folder...")
print(f"📁 Saving to: {save_dir}")
print()

for filename, url in files.items():
    filepath = os.path.join(save_dir, filename)
    print(f"⬇️  Downloading {filename}...")
    try:
        urllib.request.urlretrieve(url, filepath)
        size = os.path.getsize(filepath)
        print(f"✅ Saved — {size/1024/1024:.1f} MB\n")
    except Exception as e:
        print(f"❌ Failed: {e}\n")

print("🎉 All Tesseract files ready! Extension folder is set.")