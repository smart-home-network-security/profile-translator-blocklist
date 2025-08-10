from profile_translator_blocklist.protocols.Protocol import Protocol
from profile_translator_blocklist.protocols.mqtt import mqtt
from .utils import dicts_equal


### TEST VARIABLES ###
device = {
    "name": "device-test",
    "mac":  "11:22:33:44:55:66",
    "ipv4": "192.168.1.2"
}
policy_dict_connect = {
    "packet-type": 1,  # CONNECT
    "client-id-length": 11,
    "client-id": "temp_sensor",
    "clean-session": True,
    "keep-alive": 60
}
policy_dict_publish = {
    "packet-type": 3,  # PUBLISH
    "topic-name": "temperature",
    "payload-length": 7
}
policy_dict_regex = {
    "packet-type": 3,  # PUBLISH
    "topic-name": "duration",
    "payload-regex": "[0-9]+(\\.[0-9]+)?"
}


def test_init_protocol() -> None:
    """
    Test the factory method `init_protocol` from the Protocol class.
    """
    mqtt_instance = Protocol.init_protocol("mqtt", policy_dict_connect, device)
    assert isinstance(mqtt_instance, mqtt)
    assert mqtt_instance.protocol_name == "mqtt"
    assert mqtt_instance.protocol_data == policy_dict_connect
    assert mqtt_instance.device == device


def test_parse_connect() -> None:
    """
    Test the `parse` method of the mqtt class for a CONNECT packet.
    """
    expected = {
        "nft": [],
        "nfq": [
            {"template": "mqtt_message.packet_type == {}", "match": 1},  # CONNECT
            {"template": 'strcmp(mqtt_message.client_id, "{}") == 0',
             "match": "temp_sensor"},
            {"template": 'mqtt_message.client_id_length == {}',
             "match": 11},
            {"template": 'mqtt_message.connect_flags.clean_session == {}',
             "match": True},
            {"template": "mqtt_message.keep_alive == {}", "match": 60}
        ]
    }

    mqtt_instance = mqtt(policy_dict_connect, device)
    parsed = mqtt_instance.parse()
    assert dicts_equal(parsed, expected)


def test_parse_publish() -> None:
    """
    Test the `parse` method of the mqtt class for a PUBLISH packet.
    """
    expected = {
        "nft": [],
        "nfq": [
            {"template": "mqtt_message.packet_type == {}", "match": 3},  # PUBLISH
            {"template": 'strcmp(mqtt_message.topic_name, "{}") == 0\n \t \t&& \n \t \tcheck_payload_regex(mqtt_message.payload, strlen((char *)mqtt_message.payload),"-?[0-9]?[0-9]\\\\.[0-9]°[CF]") == 1',
             "match": "temperature"},
            {"template": "mqtt_message.payload_length == {}", "match": 7}
        ]
    }

    mqtt_instance = mqtt(policy_dict_publish, device)
    parsed = mqtt_instance.parse()
    assert dicts_equal(parsed, expected)


def test_parse_regex() -> None:
    """
    Test the `parse` method of the mqtt class for a PUBLISH packet,
    with a given payload regex.
    """
    expected = {
        "nft": [],
        "nfq": [
            {"template": "mqtt_message.packet_type == {}", "match": 3},  # PUBLISH
            {"template": 'strcmp(mqtt_message.topic_name, "{}") == 0',
             "match": policy_dict_regex["topic-name"]},
            {"template": 'check_payload_regex(mqtt_message.payload, strlen((char *)mqtt_message.payload), "{}") == 1',
             "match": policy_dict_regex["payload-regex"]}
        ]
    }

    mqtt_instance = mqtt(policy_dict_regex, device)
    parsed = mqtt_instance.parse()
    assert dicts_equal(parsed, expected)
