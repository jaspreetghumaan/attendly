"""Run every test file in this folder and print one summary.

    python tests/run_all.py

Needs Flask, Flask-WTF, qrcode and Pillow installed (the same as the app).
"""
import glob, os, subprocess, sys

here = os.path.dirname(os.path.abspath(__file__))
failed = []
for path in sorted(glob.glob(os.path.join(here, "test_*.py"))):
    name = os.path.basename(path)
    print(f"\n=== {name} ===")
    code = subprocess.run([sys.executable, path]).returncode
    if code != 0:
        failed.append(name)

print("\n" + ("ALL TEST FILES PASSED" if not failed else f"FAILED: {', '.join(failed)}"))
sys.exit(1 if failed else 0)
