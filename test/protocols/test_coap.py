from profile_translator_blocklist.protocols.Protocol import Protocol
from profile_translator_blocklist.protocols.coap import coap
from .utils import dicts_equal


### TEST VARIABLES ###
device = {
    "name": "device-test",
    "mac":  "11:22:33:44:55:66",
    "ipv4": "192.168.1.2"
}
policy_dict = {
    "type": "CON",
    "method": "GET",
    "uri": "/index.html"
}


def test_init_protocol() -> None:
    """
    Test the factory method `init_protocol` from the Protocol class.
    """
    coap_instance = Protocol.init_protocol("coap", policy_dict, device)
    assert isinstance(coap_instance, coap)
    assert coap_instance.protocol_name == "coap"
    assert coap_instance.protocol_data == policy_dict
    assert coap_instance.device == device


def test_parse_forward() -> None:
    """
    Test the method `parse` from the coap class,
    in the forward direction.
    """
    coap_instance = coap(policy_dict, device)
    
    expected = {
        "nft": [],
        "nfq": [
            {"template": "{}coap_is_request(coap_message)",
             "match": ""},
            {"template": "coap_message.type == {}",
             "match": f"COAP_{policy_dict['type']}"},
            {"template": "coap_message.method == {}",
             "match": f"HTTP_{policy_dict['method']}"},
            {"template": 'strcmp(coap_message.uri, "{}") == 0',
             "match": policy_dict['uri']}
        ]
    }
    
    parsed = coap_instance.parse()
    assert dicts_equal(parsed, expected)
