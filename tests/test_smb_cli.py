import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import nxc.cli as cli


def test_smb_parser_accepts_scshell_exec_method(monkeypatch):
    monkeypatch.setattr(cli.argcomplete, "autocomplete", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli.importlib.metadata, "version", lambda _: "1.4.0+0.deadbeef")
    monkeypatch.setattr(cli, "get_module_names", lambda: [])
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "netexec",
            "smb",
            "127.0.0.1",
            "-u",
            "user",
            "-p",
            "pass",
            "-x",
            "whoami",
            "--exec-method",
            "scshell",
        ],
    )

    args, _ = cli.gen_cli_args()

    assert args.exec_method == "scshell"
    assert args.sc_service_name == "RemoteRegistry"
    assert args.sc_no_cmd is False
