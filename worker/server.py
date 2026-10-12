#!/usr/bin/env python3
"""Private Unix-socket worker for bounded Speakeasy emulation."""

from __future__ import annotations

import base64
import json
import multiprocessing as mp
import os
import signal
import socket
import threading
import zlib
from pathlib import Path
from typing import Any

import speakeasy
from speakeasy.config import get_default_config_dict

SOCKET_PATH = os.environ.get("BACKSTREET_WORKER_SOCKET", "/run/backstreet/worker.sock")
DATA_ROOT = Path(os.environ.get("BACKSTREET_DATA_DIR", "/data")).resolve()
MAX_REQUEST = 1 << 20
MAX_ARTIFACT = int(os.environ.get("BACKSTREET_MAX_ARTIFACT_BYTES", str(64 << 20)))
CONCURRENCY = int(os.environ.get("BACKSTREET_WORKER_CONCURRENCY", "2"))


def build_config(options: dict[str, Any]) -> dict[str, Any]:
    config = get_default_config_dict()
    config["timeout"] = min(max(int(options.get("timeout_seconds", 60)), 1), 600)
    config["max_total_time"] = config["timeout"]
    config["max_api_count"] = min(max(int(options.get("max_api_count", 10_000)), 1), 1_000_000)
    if options.get("max_instructions"):
        config["max_instructions"] = int(options["max_instructions"])
    config["snapshot_memory_regions"] = bool(options.get("snapshot_memory_regions", False))
    analysis = config.setdefault("analysis", {})
    analysis["strings"] = bool(options.get("strings", False))
    analysis["coverage"] = bool(options.get("coverage", False))
    analysis["memory_tracing"] = bool(options.get("memory_tracing", False))
    if options.get("environment"):
        config.setdefault("env", {}).update(
            {str(k)[:128]: str(v)[:4096] for k, v in options["environment"].items()}
        )
    if options.get("dns_names"):
        config.setdefault("network", {}).setdefault("dns", {}).setdefault("names", {}).update(
            {str(k)[:253]: str(v)[:64] for k, v in options["dns_names"].items()}
        )
    return config


def safe_path(value: str, *, directory: bool = False) -> Path:
    path = Path(value).resolve()
    if path != DATA_ROOT and DATA_ROOT not in path.parents:
        raise ValueError("path is outside the data root")
    if directory:
        path.mkdir(parents=True, exist_ok=True)
    return path


def extract_dropped_files(report: dict[str, Any], output_dir: Path) -> list[dict[str, str]]:
    artifacts: list[dict[str, str]] = []
    data_store = report.get("data") or {}
    dropped_dir = output_dir / "dropped"
    dropped_dir.mkdir(mode=0o750, exist_ok=True)
    seen: set[str] = set()
    for entrypoint in report.get("entry_points") or []:
        for dropped in entrypoint.get("dropped_files") or []:
            ref = str(dropped.get("data_ref") or "")
            encoded = data_store.get(ref)
            if not ref or ref in seen or not isinstance(encoded, dict):
                continue
            try:
                payload = base64.b64decode(encoded["data"], validate=True)
                if encoded.get("compression") == "zlib":
                    payload = zlib.decompress(payload)
            except (KeyError, ValueError, zlib.error):
                continue
            if len(payload) > MAX_ARTIFACT:
                continue
            seen.add(ref)
            name = Path(str(dropped.get("path") or ref).replace("\\", "/")).name or ref
            target = dropped_dir / f"{len(artifacts):04d}-{name}"
            target.write_bytes(payload)
            artifacts.append(
                {
                    "kind": "dropped_file",
                    "name": name,
                    "path": str(target),
                    "content_type": "application/octet-stream",
                }
            )
    return artifacts


def analyze(request: dict[str, Any], output: mp.connection.Connection) -> None:
    emulator = None
    try:
        sample_path = safe_path(str(request["sample_path"]))
        output_dir = safe_path(str(request["output_dir"]), directory=True)
        options = request.get("options") or {}
        emulator = speakeasy.Speakeasy(
            config=build_config(options),
            argv=[str(value)[:4096] for value in options.get("argv", [])],
        )
        kind = options.get("kind", "SAMPLE_KIND_PE")
        if kind in ("SAMPLE_KIND_SHELLCODE", 2):
            arch_value = options.get("architecture", "ARCHITECTURE_X86")
            arch = "amd64" if arch_value in ("ARCHITECTURE_X64", 2) else "x86"
            address = emulator.load_shellcode(fpath=str(sample_path), arch=arch)
            emulator.run_shellcode(address)
        else:
            module = emulator.load_module(path=str(sample_path))
            emulator.run_module(module, all_entrypoints=bool(options.get("all_entrypoints", False)))
        report_json = emulator.get_json_report()
        report = json.loads(report_json)
        report_path = output_dir / "report.json"
        report_path.write_text(report_json, encoding="utf-8")
        output.send(
            {
                "ok": True,
                "report_path": str(report_path),
                "report_version": str(report.get("report_version", "")),
                "artifacts": extract_dropped_files(report, output_dir),
            }
        )
    except BaseException as exc:  # The subprocess boundary converts all failures to a stable response.
        output.send(
            {
                "ok": False,
                "error_code": type(exc).__name__,
                "error_message": str(exc)[:4096],
            }
        )
    finally:
        if emulator is not None:
            emulator.shutdown()
        output.close()


class Server:
    def __init__(self) -> None:
        self.stop = threading.Event()
        self.slots = threading.BoundedSemaphore(CONCURRENCY)
        self.threads: set[threading.Thread] = set()
        self.lock = threading.Lock()

    def handle(self, conn: socket.socket) -> None:
        process: mp.Process | None = None
        parent_pipe: mp.connection.Connection | None = None
        try:
            with conn.makefile("rb") as source:
                line = source.readline(MAX_REQUEST + 1)
            if not line or len(line) > MAX_REQUEST:
                return
            request = json.loads(line)
            if request.get("health") is True:
                self.send(conn, {"status": "ok"})
                return
            if not self.slots.acquire(timeout=5):
                self.send(conn, {"ok": False, "error_code": "busy", "error_message": "worker is busy"})
                return
            parent_pipe, child_pipe = mp.Pipe(duplex=False)
            process = mp.Process(target=analyze, args=(request, child_pipe), daemon=True)
            process.start()
            child_pipe.close()
            conn.setblocking(False)
            while process.is_alive():
                if parent_pipe.poll(0.2):
                    break
                try:
                    if conn.recv(1, socket.MSG_PEEK) == b"":
                        process.terminate()
                        return
                except BlockingIOError:
                    pass
            if parent_pipe.poll(1):
                self.send(conn, parent_pipe.recv())
            else:
                self.send(
                    conn,
                    {"ok": False, "error_code": "worker_exit", "error_message": "analysis process exited"},
                )
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            self.send(conn, {"ok": False, "error_code": "bad_request", "error_message": str(exc)[:4096]})
        finally:
            if process is not None:
                if process.is_alive():
                    process.terminate()
                process.join(timeout=2)
            if parent_pipe is not None:
                parent_pipe.close()
            if process is not None:
                self.slots.release()
            conn.close()
            with self.lock:
                self.threads.discard(threading.current_thread())

    @staticmethod
    def send(conn: socket.socket, response: dict[str, Any]) -> None:
        try:
            conn.setblocking(True)
            conn.sendall(json.dumps(response, separators=(",", ":")).encode() + b"\n")
        except OSError:
            pass

    def run(self) -> None:
        socket_path = Path(SOCKET_PATH)
        socket_path.parent.mkdir(parents=True, exist_ok=True)
        socket_path.unlink(missing_ok=True)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(SOCKET_PATH)
        os.chmod(SOCKET_PATH, 0o660)
        listener.listen(CONCURRENCY * 2)
        listener.settimeout(0.5)
        while not self.stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            thread = threading.Thread(target=self.handle, args=(conn,), daemon=True)
            with self.lock:
                self.threads.add(thread)
            thread.start()
        listener.close()
        socket_path.unlink(missing_ok=True)


if __name__ == "__main__":
    mp.set_start_method("spawn")
    server = Server()
    signal.signal(signal.SIGTERM, lambda *_: server.stop.set())
    signal.signal(signal.SIGINT, lambda *_: server.stop.set())
    server.run()
