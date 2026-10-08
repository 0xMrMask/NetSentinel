"""Live server boot check: starts main.py, hits /api/status, shuts down."""
import subprocess
import sys
import time
import urllib.request

HERE = __file__.rsplit("\\", 1)[0] if "\\" in __file__ else __file__.rsplit("/", 1)[0]

def run():
    proc = subprocess.Popen(
        [sys.executable, "main.py"],
        cwd=HERE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        time.sleep(3)
        if proc.poll() is not None:
            out, err = proc.communicate(timeout=5)
            print("Server exited early!")
            print(out.decode(errors="replace"))
            print(err.decode(errors="replace"))
            sys.exit(1)

        resp = urllib.request.urlopen("http://127.0.0.1:8000/api/status", timeout=5)
        body = resp.read().decode()
        print(f"LIVE SERVER OK -> {resp.status} {body}")

        resp = urllib.request.urlopen("http://127.0.0.1:8000/", timeout=5)
        html = resp.read().decode()
        assert "NetSentinel" in html
        print(f"INDEX OK -> {resp.status} ({len(html)} bytes)")
        print("\nLIVE SERVER TEST PASSED")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

if __name__ == "__main__":
    run()
