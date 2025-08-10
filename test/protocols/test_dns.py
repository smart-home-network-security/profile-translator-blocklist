from profile_translator_blocklist.protocols.Protocol import Protocol
from profile_translator_blocklist.protocols.dns import dns
from .utils import dicts_equal


### TEST VARIABLES ###
device = {
    "name": "device-test",
    "mac":  "11:22:33:44:55:66",
    "ipv4": "192.168.1.2"
}
policy_dict = {
    "qtype" : "A",
    "domain-name" : "www.example.com"
}
policy_dict_wildcard = {
    "qtype" : "A",
    "domain-name" : "$example.com"
}


def test_init_protocol() -> None:
    """
    Test the factory method `init_protocol` from the Protocol class.
    """
    dns_instance = Protocol.init_protocol("dns", policy_dict, device)
    assert isinstance(dns_instance, dns)
    assert dns_instance.protocol_name == "dns"
    assert dns_instance.protocol_data == policy_dict
    assert dns_instance.device == device


def test_parse_forward() -> None:
    """
    Test the method `parse` from the dns class,
    in the forward direction.
    """
    dns_instance = dns(policy_dict, device)
    
    domain_name_stripped = policy_dict["domain-name"].replace("www.", "")
    expected = {
        "nft": [],
        "nfq": [
            {"template": "dns_message.header.qr == {}",
             "match": 0},
            {"template": '( dns_message.header.qdcount > 0 && dns_message.questions->qtype == {} )',
             "match": policy_dict["qtype"]},
            {"template": f'dns_contains_suffix_domain_name(dns_message.questions, dns_message.header.qdcount, "{{}}", {len(domain_name_stripped)})',
             "match": domain_name_stripped}
        ]
    }
    
    parsed = dns_instance.parse()
    assert dicts_equal(parsed, expected)


def test_parse_backward() -> None:
    """
    Test the method `parse` from the dns class,
    in the backward direction.
    """
    dns_instance = dns(policy_dict, device)
    
    domain_name_stripped = policy_dict["domain-name"].replace("www.", "")
    expected = {
        "nft": [],
        "nfq": [
            {"template": "dns_message.header.qr == {}",
             "match": 1},
            {"template": '( dns_message.header.qdcount > 0 && dns_message.questions->qtype == {} )',
             "match": policy_dict["qtype"]},
            {"template": f'dns_contains_suffix_domain_name(dns_message.questions, dns_message.header.qdcount, "{{}}", {len(domain_name_stripped)})',
             "match": domain_name_stripped}
        ]
    }
    
    parsed = dns_instance.parse(is_backward=True)
    assert dicts_equal(parsed, expected)


def test_parse_wildcard() -> None:
    """
    Test the method `parse` from the dns class,
    with a wildcard domain name.
    """
    dns_instance = dns(policy_dict_wildcard, device)
    
    domain_name_stripped = policy_dict_wildcard["domain-name"].replace("$", "")
    expected = {
        "nft": [],
        "nfq": [
            {"template": "dns_message.header.qr == {}",
             "match": 0},
            {"template": '( dns_message.header.qdcount > 0 && dns_message.questions->qtype == {} )',
             "match": policy_dict_wildcard["qtype"]},
            {"template": f'dns_contains_suffix_domain_name(dns_message.questions, dns_message.header.qdcount, "{{}}", {len(domain_name_stripped)})',
             "match": domain_name_stripped}
        ]
    }
    
    parsed = dns_instance.parse()
    assert dicts_equal(parsed, expected)
