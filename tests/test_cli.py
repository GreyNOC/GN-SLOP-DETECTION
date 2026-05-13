import json

from app.cli import main


def test_cli_text_outputs_analysis(capsys):
    exit_code = main(["text", "This revolutionary system is guaranteed.", "--pretty"])
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["input_type"] == "text"
    assert payload["signals"]
    assert "dimensions" in payload
    assert "profile" in payload


def test_cli_file_outputs_results(tmp_path, capsys):
    sample = tmp_path / "sample.txt"
    sample.write_text("In today's fast-paced world, this is best-in-class.", encoding="utf-8")

    exit_code = main(["file", str(sample)])
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["results"]) == 1
    assert payload["results"][0]["source"] == str(sample)


def test_cli_missing_file_returns_error(tmp_path, capsys):
    exit_code = main(["file", str(tmp_path / "missing.txt")])
    assert exit_code == 1
    payload = json.loads(capsys.readouterr().err)
    assert "Path not found" in payload["error"]
