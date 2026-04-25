
import PyInstaller.__main__
import os
import shutil

print("🚀 Starting Build Process for SecureStego Pro...")

# Clean previous builds
if os.path.exists("build"): shutil.rmtree("build")
if os.path.exists("dist"): shutil.rmtree("dist")

# Define build arguments
args = [
    'stego_gui.py',                      # Main script
    '--name=SecureStegoPro',             # Executable name
    '--noconsole',                       # Hide console window
    '--onefile',                         # Single file executable
    '--clean',                           # Clean cache
    '--collect-all=tkinterdnd2',         # Collect DND library
    '--hidden-import=PIL',               # Ensure Pillow is found
    '--hidden-import=babel.numbers',     # specific Fix for some systems
]

# Add icon if available (example)
# args.append('--icon=icon.ico')

print("📦 Building Executable... (This may take 1-2 minutes)")
try:
    PyInstaller.__main__.run(args)
    print("\n✅ Build Successful!")
    print(f"📂 Executable is located in: {os.path.abspath('dist')}")
    print("👉 Look for 'SecureStegoPro.exe'")
except Exception as e:
    print(f"\n❌ Build Failed: {e}")

input("\nPress Enter to exit...")
