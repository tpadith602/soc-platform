#!/usr/bin/env python3
"""
SOC Platform Launcher — manages all four components:
  dashboard   Flask dashboard + SocketIO
  nids        Network Intrusion Detection (rule + ML)
  ml_engine   SSH brute-force monitor (auth.log tailer)
  honeypot    Low-interaction decoy services (SSH/HTTP/FTP)
"""

import subprocess
import signal
import time
import threading
from pathlib import Path

BASE_DIR    = Path(__file__).parent.parent
VENV_PYTHON = BASE_DIR / 'venv' / 'bin' / 'python'

COMPONENTS = {
    'dashboard': [str(VENV_PYTHON), str(BASE_DIR / 'web'         / 'app.py')],
    'nids':      [str(VENV_PYTHON), str(BASE_DIR / 'ingestion'   / 'nids_engine.py')],
    'ml_engine': [str(VENV_PYTHON), str(BASE_DIR / 'scripts'     / 'phase3_ingestion.py')],
    'honeypot':  [str(VENV_PYTHON), str(BASE_DIR / 'ingestion'   / 'honeypot.py')],
}


class SOCLauncher:
    def __init__(self):
        self.running   = True
        self._lock     = threading.RLock()   # RLock: watchdog calls _start() while holding it
        self.processes = {}

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _start(self, name: str) -> bool:
        try:
            proc = subprocess.Popen(
                COMPONENTS[name],
                cwd=BASE_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            with self._lock:
                # Reap any zombie left by a previous instance of this component
                old = self.processes.get(name)
                if old is not None and old.poll() is not None:
                    try:
                        old.wait(timeout=2)
                    except Exception:
                        pass
                self.processes[name] = proc
            print(f"✅ {name} started (pid {proc.pid})")
            return True
        except Exception as e:
            print(f"❌ {name} failed to start: {e}")
            return False

    def _log_output(self, name: str, proc: subprocess.Popen) -> None:
        try:
            for line in iter(proc.stdout.readline, ''):
                if line:
                    print(f"[{name}] {line.rstrip()}")
        except Exception:
            pass

    def _start_with_logger(self, name: str) -> None:
        if self._start(name):
            with self._lock:
                proc = self.processes[name]
            threading.Thread(
                target=self._log_output,
                args=(name, proc),
                daemon=True,
                name=f"Log-{name}",
            ).start()

    # ------------------------------------------------------------------ #
    # Watchdog                                                             #
    # ------------------------------------------------------------------ #

    def _watchdog(self) -> None:
        while self.running:
            time.sleep(5)
            with self._lock:
                crashed = [
                    name for name, proc in self.processes.items()
                    if proc.poll() is not None
                ]
            for name in crashed:
                if not self.running:
                    break
                print(f"⚠️  {name} exited — restarting in 3s")
                time.sleep(3)
                self._start_with_logger(name)

    # ------------------------------------------------------------------ #
    # Lifecycle                                                            #
    # ------------------------------------------------------------------ #

    def stop_all(self) -> None:
        with self._lock:
            items = list(self.processes.items())
        for name, proc in items:
            try:
                proc.terminate()
                proc.wait(timeout=5)
                print(f"✅ {name} stopped")
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                    proc.wait(timeout=2)
                    print(f"✅ {name} killed")
                except Exception:
                    pass
            except Exception:
                pass

    def run(self) -> None:
        signal.signal(signal.SIGINT,  lambda s, f: setattr(self, 'running', False))
        signal.signal(signal.SIGTERM, lambda s, f: setattr(self, 'running', False))

        print("=" * 55)
        print("🚀 SOC Platform — Unified Launcher")
        print("=" * 55)

        for name in COMPONENTS:
            self._start_with_logger(name)

        print("=" * 55)
        print("✅ All components started!")
        print("   dashboard  — http://127.0.0.1:5001")
        print("   nids       — packet capture (rule + ML)")
        print("   ml_engine  — SSH brute-force monitor")
        print(f"  honeypot   — decoy SSH:2222 / HTTP:8080 / FTP:2121")
        print("=" * 55)
        print("Press Ctrl+C to stop")

        threading.Thread(
            target=self._watchdog, name="Watchdog", daemon=True
        ).start()

        while self.running:
            time.sleep(1)

        print("\n🛑 Shutting down…")
        self.stop_all()
        print("✅ SOC Platform stopped")


if __name__ == '__main__':
    SOCLauncher().run()
