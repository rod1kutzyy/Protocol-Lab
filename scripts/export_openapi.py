"""Run with backend/.venv/bin/python scripts/export_openapi.py."""

import json
from pathlib import Path

from protocol_lab.api.app import create_app
from protocol_lab.inference.models import SCHEMAS
from protocol_lab.inference.models import json_schema as inference_schema
from protocol_lab.interpretation.schema import json_schema

root = Path(__file__).resolve().parents[1]
(root / "docs" / "openapi.json").write_text(
    json.dumps(create_app().openapi(), indent=2, ensure_ascii=False) + "\n"
)

(root / "docs" / "interpretation.schema.json").write_text(
    json.dumps(json_schema(), indent=2, ensure_ascii=False) + "\n"
)

inference = root / "docs" / "schemas" / "inference"
inference.mkdir(parents=True, exist_ok=True)
for name in SCHEMAS:
    (inference / f"{name}.schema.json").write_text(
        json.dumps(inference_schema(name), indent=2, ensure_ascii=False) + "\n"
    )
