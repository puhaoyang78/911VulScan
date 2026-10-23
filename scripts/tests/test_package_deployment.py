# Modified 2026-10-23 for the VulScan-only product namespace.
"""Deployment selection must not mistake production parsers/prompts for tests."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("package_deployment", Path(__file__).resolve().parents[1] / "package-deployment.py")
packager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packager)


class DeploymentTests(unittest.TestCase):
    def test_runtime_files(self):
        for name in ["LICENSE", "config/models.json", "apps/vulscan-cli/ui/vendor/SOURCES.txt", "apps/vulscan-cli/internal/report/vendor/report.css", "libs/vulscan-core/parsers/go/test_pipeline.py", "libs/vulscan-core/utilities/autopatcher/test_plan_discovery.py", "libs/vulscan-core/utilities/autopatcher/prompts/patch_generator.md", "libs/vulscan-core/utilities/dynamic_tester/docker_templates/c.Dockerfile", "libs/vulscan-core/vulscan/__main__.py"]:
            self.assertTrue(packager.included(name), name)

    def test_development_excluded(self):
        for name in [".git/config", "CHANGELOG.md", "libs/vulscan-core/tests/test_scanner.py", "apps/vulscan-cli/cmd/root_test.go", "apps/vulscan-cli/internal/server/testdata/a.html", "libs/vulscan-core/core/__pycache__/a.pyc", "libs/vulscan-core/parsers/javascript/node_modules/a.js", "libs/vulscan-core/utilities/autopatcher/tools/run_cve_batch.py", "config/testdata/detection_parity.json"]:
            self.assertFalse(packager.included(name), name)

    def test_only_new_product_namespace(self):
        names = {p.relative_to(packager.ROOT).as_posix() for p in packager.selected(packager.ROOT)}
        self.assertFalse(any("openant" in name.lower() for name in names))
        installer = (packager.ROOT / "scripts/install-deployment.sh").read_text()
        self.assertNotIn("OPENANT_", installer)
        self.assertNotIn("bin/openant", installer)
        self.assertIn('export VULSCAN_PYTHON=', installer)

    def test_registered_parser_entrypoints(self):
        registry = json.loads((packager.ROOT / "config/languages.json").read_text())
        names = {p.relative_to(packager.ROOT).as_posix() for p in packager.selected(packager.ROOT)}
        for language in registry["languages"].values():
            script = language["parser"].get("script")
            if script:
                self.assertIn(packager.CORE + script, names)

    def test_reproducible(self):
        with tempfile.TemporaryDirectory() as temp:
            first, second = Path(temp) / "a.tar.gz", Path(temp) / "b.tar.gz"
            packager.package(packager.ROOT, first)
            packager.package(packager.ROOT, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())


if __name__ == "__main__":
    unittest.main()
