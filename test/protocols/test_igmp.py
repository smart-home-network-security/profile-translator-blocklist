from profile_translator_blocklist.protocols.Protocol import Protocol
from profile_translator_blocklist.protocols.igmp import igmp
from .utils import dicts_equal


### TEST VARIABLES ###
device = {
    "name": "device-test",
    "mac":  "11:22:33:44:55:66",
    "ipv4": "192.168.1.2"
}
policy_dict_version_2 = {
    "version": 2,
    "type": "membership report",
    "group": "ssdp"
}
policy_dict_version_3 = {
    "version": 3,
    "type": "membership report",
    "group": "ssdp"
}


def test_init_protocol() -> None:
    """
    Test the factory method `init_protocol` from the Protocol class.
    """
    igmp_instance = Protocol.init_protocol("igmp", policy_dict_version_2, device)
    assert isinstance(igmp_instance, igmp)
    assert igmp_instance.protocol_name == "igmp"
    assert igmp_instance.protocol_data == policy_dict_version_2
    assert igmp_instance.device == device


def test_parse_version_2() -> None:
        """
        Test the method `parse` from the igmp class.
        """
        igmp_instance = igmp(policy_dict_version_2, device)
        
        expected = {
            "nft": [
                {"template": "meta l4proto {}", "match": 2}
            ],
            "nfq": [
                {"template": "igmp_message.type == V2_{}",
                 "match": "MEMBERSHIP_REPORT"},
                {"template": 'strcmp(ipv4_net_to_str(igmp_message.body.v2_message.group_address), "{}") == 0',
                 "match": igmp.groups[igmp_instance.protocol_data["group"]]}
            ]
        }
        
        parsed = igmp_instance.parse()
        assert dicts_equal(parsed, expected)


def test_parse_version_3() -> None:
        """
        Test the method `parse` from the igmp class.
        """
        igmp_instance = igmp(policy_dict_version_3, device)
        
        expected = {
            "nft": [
                {"template": "meta l4proto {}", "match": 2}
            ],
            "nfq": [
                {"template": "igmp_message.type == V3_{}",
                 "match": "MEMBERSHIP_REPORT"},
                {"template": 'strcmp(ipv4_net_to_str((igmp_message.body.v3_membership_report.groups)->group_address), "{}") == 0',
                 "match": igmp.groups[igmp_instance.protocol_data["group"]]}
            ]
        }
        
        parsed = igmp_instance.parse()
        assert dicts_equal(parsed, expected)
