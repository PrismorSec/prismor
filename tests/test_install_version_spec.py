"""A partial or range version spec is not an exact version (#599)."""
import pytest

from supplychain.ecosystems.detector import detect_install


@pytest.mark.parametrize("argv, version", [
    (["npm", "i", "playwright@1"], ""),
    (["npm", "install", "react@^1.2"], ""),
    (["npm", "install", "lodash@~3"], ""),
    (["npm", "install", "next@latest"], ""),
    (["npm", "install", "@scope/pkg@>=2.0.0"], ""),
    (["pip", "install", "django==4.*"], ""),
    (["npm", "install", "playwright@1.48.2"], "1.48.2"),
    (["npm", "install", "@scope/pkg@2.0.0-beta.1"], "2.0.0-beta.1"),
    (["cargo", "add", "serde@1.0.210"], "1.0.210"),
    (["pip", "install", "django==4.2"], "4.2"),
    (["pip", "install", "requests[socks]==2.32.3"], "2.32.3"),
])
def test_only_exact_versions_are_pinned(argv, version):
    (spec,) = detect_install(argv).packages
    assert spec.version == version
