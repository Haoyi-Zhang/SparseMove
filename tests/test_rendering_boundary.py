"""Optional paper rendering must not widen scientific dependencies."""
from pathlib import Path
import importlib.util
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class RenderingBoundary(unittest.TestCase):
    def test_optional_plotting_does_not_allow_production_dependencies(self):
        spec = importlib.util.spec_from_file_location(
            'artifact_dependency_audit', ROOT / 'scripts/verify_artifact.py')
        audit = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(audit)
        # This scans both shipped plotting tools without importing Matplotlib.
        audit.audit_python_sources()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'src').mkdir()
            (root / 'src/analysis.py').write_text('import matplotlib\n', encoding='utf-8')
            with patch.object(audit, 'ROOT', root):
                with self.assertRaisesRegex(RuntimeError, 'non-standard dependency'):
                    audit.audit_python_sources()


if __name__ == '__main__':
    unittest.main(verbosity=2)
