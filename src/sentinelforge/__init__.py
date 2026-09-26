"""SentinelForge - environment-aware detection engineering library.

    pip install sentinelforge-detect

    from sentinelforge import Engine
    engine = Engine.from_paths(["builtin", "./my-rules"], inventory="host-inventory.json")
    detections = engine.process({"source": "windows", "data": {...}})

Originally created by Sujhal Gurav. Licensed under the Apache License, Version 2.0.
"""

__version__ = "0.2.0"
__project__ = "SentinelForge"
__creator__ = "Sujhal Gurav"
__license__ = "Apache-2.0"

from sentinelforge.engine import DetectionEngine, Engine  # noqa: E402
from sentinelforge.inventory import InventoryError, load_inventory, parse_inventory  # noqa: E402
from sentinelforge.normalize import NormalizationError, normalize  # noqa: E402
from sentinelforge.profiling import build_profile  # noqa: E402
from sentinelforge.rules.loader import load_rule_paths, validate_rule_text  # noqa: E402

__all__ = ["Engine", "DetectionEngine", "normalize", "NormalizationError", "build_profile", "parse_inventory",
           "load_inventory", "InventoryError", "load_rule_paths", "validate_rule_text", "__version__"]
