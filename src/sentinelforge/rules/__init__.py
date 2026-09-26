"""Rule templates: loading/validation (loader), safe evaluation (evaluator), environment selection
(selection), unit tests (testing) and ATT&CK coverage (coverage)."""

from pathlib import Path


def builtin_rules_path() -> Path:
    """The built-in rule packs: bundled in the wheel, or the repository's detection-rules/ in a source checkout."""
    bundled = Path(__file__).resolve().parent.parent / "rulepacks" / "builtin"
    if bundled.is_dir():
        return bundled
    return Path(__file__).resolve().parents[3] / "detection-rules"
