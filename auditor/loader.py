"""Read container configs from a local JSON file."""

from __future__ import annotations

import json
from pathlib import Path

FILE_ENCODING = "utf-8"


class ConfigError(Exception):
    """The input file cannot be read or does not hold container configs."""


def load_configs(path: Path) -> list[object]:
    """Read a JSON file holding one container config or a list of them.

    Always returns a list. Entries are returned as parsed, without checking
    their shape: an entry that is not an object is a finding about that
    container, not a reason to reject the whole file.

    Raises ConfigError if the file can't be read, isn't valid UTF-8 JSON, or
    its top level is not an object or a non-empty list.
    """
    try:
        text = path.read_text(encoding=FILE_ENCODING)
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{path} is not valid {FILE_ENCODING} text") from exc

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"{path} is not valid JSON: {exc.msg} "
            f"(line {exc.lineno}, column {exc.colno})"
        ) from exc

    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        if not data:
            raise ConfigError(f"{path} contains an empty list; nothing to audit")
        return data
    raise ConfigError(
        f"{path} must hold a JSON object or a list of objects, "
        f"not {type(data).__name__}"
    )
