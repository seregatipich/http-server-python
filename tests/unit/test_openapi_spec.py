"""Validate the published OpenAPI specification and its multi-file layout."""

from pathlib import Path

import pytest
import yaml
from openapi_spec_validator import validate
from openapi_spec_validator.readers import read_from_filename

DOCS = Path(__file__).resolve().parents[2] / "docs"
ROOT_SPEC = DOCS / "openapi.yaml"
SPEC_FILES = (
    DOCS / "openapi.yaml",
    DOCS / "openapi.paths.yaml",
    DOCS / "openapi.components.yaml",
)
MAX_SPEC_FILE_LINES = 500
EXPECTED_PATHS = {
    "/",
    "/healthz",
    "/echo/{message}",
    "/user-agent",
    "/files/{path}",
    "/metrics",
}


def test_spec_is_valid_openapi() -> None:
    """The root spec resolves its external $refs and validates as OpenAPI 3.1."""
    spec, base_uri = read_from_filename(str(ROOT_SPEC))
    validate(spec, base_uri=base_uri)
    assert spec["openapi"].startswith("3.1")


def test_spec_exposes_expected_routes() -> None:
    """Every documented route is present and references a resolvable path item."""
    spec = yaml.safe_load(ROOT_SPEC.read_text())
    assert set(spec["paths"]) == EXPECTED_PATHS
    for path_item in spec["paths"].values():
        assert path_item["$ref"].startswith("./openapi.paths.yaml#/")


def test_component_fragments_parse() -> None:
    """The paths and components fragments are well-formed YAML mappings."""
    paths = yaml.safe_load((DOCS / "openapi.paths.yaml").read_text())
    components = yaml.safe_load((DOCS / "openapi.components.yaml").read_text())
    assert {"Index", "Healthz", "Echo", "UserAgent", "Files", "Metrics"} <= set(paths)
    assert set(components) == {"parameters", "headers", "responses"}


@pytest.mark.parametrize("spec_file", SPEC_FILES, ids=lambda p: p.name)
def test_spec_files_stay_within_line_budget(spec_file: Path) -> None:
    """Each fragment stays under the structural line-length budget."""
    line_count = len(spec_file.read_text().splitlines())
    assert line_count < MAX_SPEC_FILE_LINES, f"{spec_file.name} has {line_count} lines"
