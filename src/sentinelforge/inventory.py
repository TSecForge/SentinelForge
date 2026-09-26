"""Parse and validate collector output (inventory schema 1.0)."""

import json
from pathlib import Path

from pydantic import ValidationError

from sentinelforge.schemas.inventory import Inventory

MAX_INVENTORY_BYTES = 50 * 1024 * 1024


class InventoryError(Exception):
    pass


def parse_inventory(raw: str | bytes | dict) -> Inventory:
    """Validate collector output. Accepts JSON text (UTF-8, optional BOM) or an already-decoded dict."""
    if isinstance(raw, (str, bytes)):
        if len(raw) > MAX_INVENTORY_BYTES:
            raise InventoryError("inventory too large")
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8-sig", errors="replace")
        try:
            raw = json.loads(raw.lstrip("﻿"))
        except json.JSONDecodeError as e:
            raise InventoryError(f"collector output is not valid JSON: {e}") from e
    try:
        return Inventory.model_validate(raw)
    except ValidationError as e:
        raise InventoryError(f"inventory failed schema validation: {e.errors()[:5]}") from e


def load_inventory(path: str | Path) -> Inventory:
    return parse_inventory(Path(path).read_bytes())
