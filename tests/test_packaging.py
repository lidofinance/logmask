import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
# mutmut copies the package into mutants/ and adds its own import to every module.
UNDER_MUTMUT = 'mutants' in ROOT.parts


def test_package_declares_no_runtime_dependencies():
    """Hard rule of the project: the library pulls nothing at runtime.

    Tools for tests, lint and types live in the dev group only.
    """
    project = tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']

    assert project['dependencies'] == []
    assert 'optional-dependencies' not in project


@pytest.mark.skipif(UNDER_MUTMUT, reason='mutmut adds its own import to the mutated modules')
def test_package_imports_only_the_standard_library():
    third_party = []
    for module in (ROOT / 'logmask').glob('*.py'):
        for line in module.read_text().splitlines():
            if line.startswith(('import ', 'from ')) and not line.startswith('from .'):
                name = line.split()[1].split('.')[0]
                if name not in sys.stdlib_module_names:
                    third_party.append(f'{module.name}: {line}')

    assert third_party == []
