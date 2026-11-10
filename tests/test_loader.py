"""Tests for auditor.loader."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from auditor.loader import ConfigError, load_configs


class LoadConfigsTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def _write(self, content: str | bytes) -> Path:
        path = self.dir / "configs.json"
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path

    def test_single_object_becomes_one_item_list(self) -> None:
        path = self._write('{"container_name": "a"}')
        self.assertEqual(load_configs(path), [{"container_name": "a"}])

    def test_list_is_returned_as_is(self) -> None:
        path = self._write('[{"container_name": "a"}, {"container_name": "b"}]')
        self.assertEqual(
            load_configs(path), [{"container_name": "a"}, {"container_name": "b"}]
        )

    def test_non_object_entries_are_kept_for_the_auditor_to_report(self) -> None:
        path = self._write('[{"container_name": "a"}, 42]')
        self.assertEqual(load_configs(path), [{"container_name": "a"}, 42])

    def test_missing_file_raises_config_error(self) -> None:
        with self.assertRaisesRegex(ConfigError, "cannot read"):
            load_configs(self.dir / "missing.json")

    def test_directory_instead_of_file_raises_config_error(self) -> None:
        with self.assertRaisesRegex(ConfigError, "cannot read"):
            load_configs(self.dir)

    def test_invalid_json_reports_location(self) -> None:
        path = self._write('{"privileged": true,,}')
        with self.assertRaisesRegex(ConfigError, r"not valid JSON.*line 1"):
            load_configs(path)

    def test_non_utf8_file_raises_config_error(self) -> None:
        path = self._write(b'{"name": "\xff"}')
        with self.assertRaisesRegex(ConfigError, "utf-8"):
            load_configs(path)

    def test_empty_list_raises_config_error(self) -> None:
        path = self._write("[]")
        with self.assertRaisesRegex(ConfigError, "empty list"):
            load_configs(path)

    def test_scalar_top_level_raises_config_error(self) -> None:
        cases = (("42", "int"), ('"text"', "str"), ("null", "NoneType"))
        for content, type_name in cases:
            with self.subTest(content=content):
                path = self._write(content)
                with self.assertRaisesRegex(ConfigError, type_name):
                    load_configs(path)


if __name__ == "__main__":
    unittest.main()
