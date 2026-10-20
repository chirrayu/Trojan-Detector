"""Optional YARA rule loading and file scanning."""

from __future__ import annotations

from pathlib import Path

from trojandetector.logger import log

DEFAULT_RULE_DIR = Path(__file__).resolve().parents[2] / "rules" / "yara"


def compile_rules(rule_path: str | Path | None = None):
    """Compile a YARA file or directory, returning ``None`` if unavailable."""
    try:
        import yara
    except ImportError:
        log.warning("YARA scanning unavailable: install the optional yara-python package")
        return None

    path = Path(rule_path) if rule_path else DEFAULT_RULE_DIR
    if path.is_file():
        return yara.compile(filepath=str(path))
    if not path.is_dir():
        log.warning("YARA rules path does not exist: %s", path)
        return None

    files = sorted(path.glob("*.yar")) + sorted(path.glob("*.yara"))
    if not files:
        return None
    namespace_rules = {f"rules_{i}": str(file) for i, file in enumerate(files)}
    try:
        return yara.compile(filepaths=namespace_rules)
    except yara.Error as exc:
        log.warning("Could not compile YARA rules from %s: %s", path, exc)
        return None


def scan_with_yara(file_path: str | Path, rule_path: str | Path | None = None) -> list[str]:
    """Return matching YARA rule identifiers for ``file_path``."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(path)
    rules = compile_rules(rule_path)
    if rules is None:
        return []
    try:
        return sorted({match.rule for match in rules.match(str(path))})
    except Exception as exc:
        log.warning("YARA scan failed for %s: %s", path, exc)
        return []
