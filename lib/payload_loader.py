"""
Payload Loader
===============
Load and validate test payloads from YAML files.

Allows security analysts and consultants to add test cases by editing
YAML files without touching Python code. Each YAML file is validated
against its corresponding Pydantic model to catch errors early.

Usage:
    from lib.payload_loader import load_payloads

    payloads = load_payloads(
        yaml_path="attacks/prompt-injection/payloads.yaml",
        model_class=InjectionPayload,
    )
"""

import logging
from pathlib import Path

from pydantic import BaseModel, ValidationError

logger = logging.getLogger("llm_security_lab")


def load_payloads[T: BaseModel](
    yaml_path: str | Path,
    model_class: type[T],
    *,
    fallback: list[T] | None = None,
) -> list[T]:
    """
    Load test payloads from a YAML file and validate each entry against
    the given Pydantic model class.

    Parameters
    ----------
    yaml_path : str | Path
        Path to the YAML file containing payload definitions.
    model_class : type[T]
        Pydantic model class to validate each payload entry against.
    fallback : list[T], optional
        If provided, returned when the YAML file is missing or unreadable.
        This lets test modules keep their hardcoded payloads as a fallback
        during the transition period.

    Returns
    -------
    list[T]
        Validated payload objects.

    Raises
    ------
    FileNotFoundError
        If the YAML file doesn't exist and no fallback is provided.
    ValueError
        If any payload entry fails Pydantic validation.
    """
    try:
        import yaml
    except ImportError:
        if fallback is not None:
            logger.info("PyYAML not installed — using hardcoded payloads")
            return fallback
        raise ImportError(
            "PyYAML is required to load YAML payloads. "
            "Install it with: pip install pyyaml"
        ) from None

    path = Path(yaml_path)

    if not path.exists():
        if fallback is not None:
            logger.info("YAML file %s not found — using hardcoded payloads", path)
            return fallback
        raise FileNotFoundError(f"Payload file not found: {path}")

    raw_data = yaml.safe_load(path.read_text(encoding="utf-8"))

    if not isinstance(raw_data, list):
        raise ValueError(
            f"Expected a YAML list of payloads in {path}, "
            f"got {type(raw_data).__name__}"
        )

    payloads: list[T] = []
    errors: list[str] = []

    for i, entry in enumerate(raw_data):
        try:
            payloads.append(model_class(**entry))
        except ValidationError as exc:
            entry_id = entry.get("id", f"index {i}")
            errors.append(f"  [{entry_id}]: {exc}")

    if errors:
        error_detail = "\n".join(errors)
        raise ValueError(
            f"Validation errors in {path}:\n{error_detail}"
        )

    logger.info("Loaded %d payloads from %s", len(payloads), path)
    return payloads
