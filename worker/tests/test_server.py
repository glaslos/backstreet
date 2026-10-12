import base64
import json
import zlib

import pytest

from worker import server


class FakePipe:
    def __init__(self):
        self.value = None

    def send(self, value):
        self.value = value

    def close(self):
        pass


def test_build_config_only_maps_safe_options():
    config = server.build_config(
        {
            "timeout_seconds": 30,
            "max_api_count": 123,
            "coverage": True,
            "environment": {"TEMP": "C:\\Temp"},
            "dns_names": {"example.org": "192.0.2.1"},
            "volumes": ["/etc:/guest"],
            "gdbPort": 1234,
        }
    )
    assert config["timeout"] == 30
    assert config["max_api_count"] == 123
    assert config["analysis"]["coverage"] is True
    assert config["env"]["TEMP"] == "C:\\Temp"
    assert config["network"]["dns"]["names"]["example.org"] == "192.0.2.1"
    assert "volumes" not in config
    assert "gdb_port" not in config


def test_safe_path_rejects_escape(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "DATA_ROOT", tmp_path.resolve())
    assert server.safe_path(str(tmp_path / "sample")) == tmp_path / "sample"
    with pytest.raises(ValueError):
        server.safe_path(str(tmp_path.parent / "escape"))


def test_extract_dropped_files(tmp_path):
    payload = b"dropped"
    report = {
        "data": {
            "ref": {
                "compression": "zlib",
                "encoding": "base64",
                "data": base64.b64encode(zlib.compress(payload)).decode(),
            }
        },
        "entry_points": [{"dropped_files": [{"path": "C:\\Temp\\drop.bin", "data_ref": "ref"}]}],
    }
    artifacts = server.extract_dropped_files(report, tmp_path)
    assert len(artifacts) == 1
    assert artifacts[0]["name"] == "drop.bin"
    assert (tmp_path / "dropped" / "0000-drop.bin").read_bytes() == payload


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        ({"kind": 1, "all_entrypoints": True}, ("module", True)),
        ({"kind": 2, "architecture": 2}, ("shellcode", "amd64")),
    ],
)
def test_analyze_dispatches_sample_kind(tmp_path, monkeypatch, options, expected):
    calls = []

    class FakeEmulator:
        def __init__(self, **_):
            pass

        def load_module(self, path):
            calls.append(("load_module", path))
            return "module"

        def run_module(self, module, all_entrypoints):
            calls.append(("module", all_entrypoints))

        def load_shellcode(self, fpath, arch):
            calls.append(("load_shellcode", fpath, arch))
            return 4096

        def run_shellcode(self, address):
            calls.append(("shellcode", "amd64" if address == 4096 else "unexpected"))

        def get_json_report(self):
            return json.dumps({"report_version": "5.0.0", "entry_points": []})

        def shutdown(self):
            calls.append(("shutdown",))

    monkeypatch.setattr(server, "DATA_ROOT", tmp_path.resolve())
    monkeypatch.setattr(server.speakeasy, "Speakeasy", FakeEmulator)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    pipe = FakePipe()
    server.analyze(
        {
            "sample_path": str(sample),
            "output_dir": str(tmp_path / "output"),
            "options": options,
        },
        pipe,
    )
    assert pipe.value["ok"] is True
    assert expected in calls
    assert calls[-1] == ("shutdown",)


def test_analyze_returns_stable_error(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "DATA_ROOT", tmp_path.resolve())
    pipe = FakePipe()
    server.analyze({"output_dir": str(tmp_path / "output"), "options": {}}, pipe)
    assert pipe.value["ok"] is False
    assert pipe.value["error_code"] == "KeyError"
