"""Line-preserving YAML loader built on PyYAML SafeLoader."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import yaml


class LineDict(dict):
    """Dictionary subclass that tracks 1-based line and column positions for keys."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.__line__: int = 1
        self.__col__: int = 1
        self._key_lines: dict[str, tuple[int, int]] = {}

    def set_key_pos(self, key: str, line: int, col: int) -> None:
        self._key_lines[str(key)] = (line, col)

    def get_key_line(self, key: str, default: int | None = None) -> int:
        if key in self._key_lines:
            return self._key_lines[key][0]
        return default if default is not None else self.__line__

    def get_key_col(self, key: str, default: int | None = None) -> int:
        if key in self._key_lines:
            return self._key_lines[key][1]
        return default if default is not None else self.__col__


class LineList(list):
    """List subclass that tracks 1-based line and column positions."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.__line__: int = 1
        self.__col__: int = 1


# The C parser is far faster where PyYAML was built with it, and reports the same marks
class _LinePreservingSafeLoader(getattr(yaml, "CSafeLoader", yaml.SafeLoader)):
    """YAML SafeLoader that attaches 1-based line/column metadata to mappings and sequences."""


def _construct_mapping(loader: _LinePreservingSafeLoader, node: yaml.MappingNode) -> LineDict:
    loader.flatten_mapping(node)
    mapping = LineDict()
    mapping.__line__ = node.start_mark.line + 1
    mapping.__col__ = node.start_mark.column + 1
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=False)
        # In YAML 1.1 (PyYAML default), unquoted `on` is parsed as boolean True.
        # Normalize boolean True key at top-level workflow trigger to "on".
        if key is True and key_node.value.lower() == "on":
            key = "on"
        value = loader.construct_object(value_node, deep=True)
        mapping[key] = value
        mapping.set_key_pos(str(key), key_node.start_mark.line + 1, key_node.start_mark.column + 1)
    return mapping


def _construct_sequence(loader: _LinePreservingSafeLoader, node: yaml.SequenceNode) -> LineList:
    seq = LineList(loader.construct_sequence(node, deep=True))
    seq.__line__ = node.start_mark.line + 1
    seq.__col__ = node.start_mark.column + 1
    return seq


_LinePreservingSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)
_LinePreservingSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_SEQUENCE_TAG,
    _construct_sequence,
)


def load_yaml_with_lines(text: str) -> tuple[LineDict | None, list[str]]:
    """Parse YAML content and return (parsed_root_dict, raw_lines)."""
    lines = text.splitlines()
    data = yaml.load(text, Loader=_LinePreservingSafeLoader)
    if isinstance(data, LineDict):
        return data, lines
    return None, lines


def load_workflow_file(path: Path) -> tuple[LineDict | None, list[str]]:
    """Read a YAML file from disk and return (parsed_root_dict, raw_lines)."""
    content = path.read_text(encoding="utf-8")
    return load_yaml_with_lines(content)
