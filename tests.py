import unittest
from pyfiscan import is_not_secure


class CompareVersions(unittest.TestCase):
    """Testing that comparison of version numbers are correct. No setup needed for these."""
    def test_version_pairs_1(self):
        self.assertTrue(is_not_secure('2.1', '2.0.2'))

    def test_version_pairs_2(self):
        self.assertTrue(is_not_secure('2.0.1', '2.0'))

    def test_version_pairs_3(self):
        self.assertTrue(is_not_secure('2.0.1', '2.0.0'))

    def test_version_pairs_4(self):
        self.assertFalse(is_not_secure('2.0.2', '2.0.2'))

    def test_version_pairs_5(self):
        self.assertFalse(is_not_secure('2.0.1', '2.0.2'))

    def test_version_pairs_6(self):
        self.assertFalse(is_not_secure('2.0', '2.0.2'))

    def test_version_pairs_7(self):
        self.assertTrue(is_not_secure('2.0', '1.9.9'))

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(CompareVersions)
    unittest.TextTestRunner(verbosity=2).run(suite)
