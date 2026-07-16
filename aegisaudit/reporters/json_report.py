from pathlib import Path
from aegisaudit.models import ScanResult


def generate_json_report(result: ScanResult, output_path: Path) -> None:
    """Generate a canonical JSON report."""
    with open(output_path, "w") as f:
        # Pydantic v2 dump_json would be nicer but model_dump_json gives string.
        # Writing directly helps formatting.
        f.write(result.model_dump_json(indent=2))
