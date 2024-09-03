import os
from pathlib import Path
import unittest
import profile_translator_blocklist

# Paths
self_name = os.path.basename(__file__)
self_path = Path(os.path.abspath(__file__))
self_dir = self_path.parents[0]
sample_profile = os.path.join(self_dir, 'profile.yaml')


class TestProfileTranslator(unittest.TestCase):
    """
    Test class for the package `profile-translator`.
    """
    
    def test_translate_profile(self):
        profile_translator_blocklist.translate_profile(sample_profile)


### MAIN ###
if __name__ == '__main__':
    unittest.main()
