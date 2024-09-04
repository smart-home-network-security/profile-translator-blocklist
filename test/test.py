import os
from pathlib import Path
import unittest
import profile_translator_blocklist

# Paths
self_name = os.path.basename(__file__)
self_path = Path(os.path.abspath(__file__))
self_dir = self_path.parents[0]


class TestProfileTranslator(unittest.TestCase):
    """
    Test class for the package `profile-translator`.
    """


    def test_translate_policy(self):
        """
        Test the function `translate_policy` from the package `profile-translator`.
        """
        device = {
            "name": "sample-device",
            "ipv4": "192.168.1.2"
        }
        policy_dict = {
            "protocols": {
                "dns": {
                    "domain-name": "example.com",
                    "qtype": "A"
                },
                "udp": {
                    "dst-port": 53
                },
                "ipv4": {
                    "src": "self",
                    "dst": "192.168.1.1"
                }
            },
            "bidirectional": True
        }

        profile_translator_blocklist.translate_policy(device, policy_dict)

    
    def test_translate_profile(self):
        """
        Test the function `translate_profile` from the package `profile-translator`.
        """
        sample_profile = os.path.join(self_dir, 'profile.yaml')
        profile_translator_blocklist.translate_profile(sample_profile)


### MAIN ###
if __name__ == '__main__':
    unittest.main()
