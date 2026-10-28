from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]


def direct_requirements(path):
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line.startswith("-r "):
            yield from direct_requirements(path.parent / line[3:].strip())
        elif line:
            yield Requirement(line)


@pytest.mark.parametrize("name", ["requirements", "requirements-dev"])
def test_direct_requirements_remain_in_hash_locked_output(name):
    # Generated updates must not silently omit installer tooling such as pip.
    blocks = (ROOT / f"{name}.txt").read_text().replace("\\\n", " ").splitlines()
    locked = {}
    for block in blocks:
        if not block or block.startswith(("#", " ")):
            continue
        requirement, _, hashes = block.partition(" --hash=")
        parsed = Requirement(requirement.strip())
        locked[canonicalize_name(parsed.name)] = (parsed, hashes)
    for requirement in direct_requirements(ROOT / f"{name}.in"):
        key = canonicalize_name(requirement.name)
        assert key in locked, f"Direct requirement {requirement} missing from {name}.txt"
        parsed, hashes = locked[key]
        assert parsed.specifier == requirement.specifier, str(requirement)
        assert "sha256:" in hashes, f"Direct requirement {requirement} lacks a SHA-256 hash"
