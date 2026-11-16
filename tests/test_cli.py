import pytest

from src.cli import main


def test_cli_file_roundtrip_and_wipe(tmp_path, monkeypatch, capsys):
    passwords = iter([
        "master-password", "master-password",  # register
        "master-password",  # encrypt
        "master-password",  # decrypt
    ])
    monkeypatch.setattr(main.getpass, "getpass", lambda prompt: next(passwords))
    main.main(["register", "-u", "alice"])
    source = tmp_path / "source.txt"
    source.write_bytes(b"file secret")
    main.main(["encrypt", "-u", "alice", "-i", str(source), "-o", "stored.txt"])
    output = tmp_path / "output.txt"
    main.main(["decrypt", "-u", "alice", "-i", "stored.txt", "-o", str(output)])
    assert output.read_bytes() == b"file secret"
    main.main(["wipe", str(source), "-y"])
    assert not source.exists()


def test_cli_failure_is_generic(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(main.getpass, "getpass", lambda prompt: "bad-password")
    with pytest.raises(SystemExit) as exc:
        main.main(["login", "-u", "unknown"])
    assert exc.value.code == 1
    assert "Invalid username or password." in capsys.readouterr().err
