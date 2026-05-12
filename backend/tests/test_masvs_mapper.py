import unittest
import sys
import os

# Add backend to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.mapping.masvs_mapper import MOBSF_TO_MASVS_MAP, _find_best_masvs_match

class TestMASVSMapper(unittest.TestCase):
    def test_hardcoded_secret_maps_to_storage_1(self):
        control, severity = _find_best_masvs_match("hardcoded_secret")
        self.assertEqual(control, "MASVS-STORAGE-1")
        self.assertEqual(severity, "high")

    def test_trust_all_certs_maps_to_network_2(self):
        control, severity = _find_best_masvs_match("trust_all_certs")
        self.assertEqual(control, "MASVS-NETWORK-2")
        self.assertEqual(severity, "critical")

    def test_unknown_code_returns_none(self):
        control, severity = _find_best_masvs_match("nonexistent_code_xyz")
        self.assertIsNone(control)
        self.assertIsNone(severity)

    def test_all_mapping_entries_have_required_structure(self):
        # Verify the table has exactly 61 entries as claimed
        self.assertEqual(len(MOBSF_TO_MASVS_MAP), 61)
        
        valid_severities = ["info", "low", "medium", "high", "critical"]
        for code, mapping in MOBSF_TO_MASVS_MAP.items():
            self.assertIsInstance(mapping, tuple)
            self.assertEqual(len(mapping), 2)
            control, severity = mapping
            self.assertTrue(control.startswith("MASVS-"))
            self.assertIn(severity, valid_severities)

if __name__ == "__main__":
    unittest.main()
