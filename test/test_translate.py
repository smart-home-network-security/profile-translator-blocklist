import os
from pathlib import Path
from profile_translator_blocklist import translate_policy, translate_profile

# Paths
self_name = os.path.basename(__file__)
self_path = Path(os.path.abspath(__file__))
self_dir = self_path.parents[0]


### TEST FUNCTIONS ###

def test_translate_policy() -> None:
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
    
    translate_policy(device, policy_dict)


def test_translate_profile() -> None:
    """
    Test the function `translate_profile` from the package `profile-translator`.
    """
    sample_profile = os.path.join(self_dir, 'profile.yaml')
    translate_profile(sample_profile)
