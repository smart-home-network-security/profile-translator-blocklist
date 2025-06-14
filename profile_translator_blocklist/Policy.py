## Import packages
from __future__ import annotations
from enum import Enum
from typing import Tuple, Dict
import ipaddress
## Custom libraries
from .LogType import LogType
# Protocol translators
from .protocols.Protocol import Protocol
from .protocols.ip import ip
# Logging
import importlib
import logging
module_relative_path = importlib.import_module(__name__).__name__
logger = logging.getLogger(module_relative_path)


class Policy:
    """
    Class which represents a single access control policy.
    """

    class NftType(Enum):
        """
        Enum: NFTables types.
        Possible values:
            - MATCH: nftables match
            - ACTION: nftables action
        """
        MATCH = 1
        ACTION = 2

    # Metadata for supported nftables statistics
    stats_metadata = {
        "rate": {"nft_type": NftType.MATCH, "counter": False, "template": "limit rate over {}"},
        "packet-size": {"nft_type": NftType.MATCH, "counter": False, "template": "ip length {}"},
        "packet-count": {"counter": True},
        "duration": {"counter": True}
    }


    def __init__(self, profile_data: dict, device: dict, policy_name: str = None, is_backward: bool = False) -> None:
        """
        Initialize a new Policy object.

        :param profile_data: Dictionary containing the policy data from the YAML profile
        :param policy_name: Name of the policy
        :param device: Dictionary containing the device metadata from the YAML profile
        :param is_backward: Whether the policy is backwards (i.e. the source and destination are reversed)
        """
        # Initialize attributes
        self.device = device                      # Dictionary containing data for the device this policy is linked to
        self.is_backward = is_backward            # Whether the policy is backwards (i.e. the source and destination are reversed)
        self.custom_parser = ""                   # Name of the custom parser (if any)
        self.nft_matches = []                     # List of nftables matches (will be populated by parsing)
        self.nft_match = ""                       # Complete nftables match (including rate and packet size)
        self.nft_stats = {}                       # Dict of nftables statistics (will be populated by parsing)
        self.queue_num = -1                       # Number of the corresponding NFQueue (will be updated by parsing)
        self.nft_action = ""                      # nftables action associated to this policy
        self.nfq_matches = []                     # List of nfqueue matches (will be populated by parsing)
        self.profile_data = profile_data          # Policy data from the YAML profile
        self.initiator = profile_data["initiator"] if "initiator" in profile_data else ""

        # Parse policy data
        self.parse()

        # Set policy name
        self.name = policy_name if policy_name is not None else self.get_name()

    
    def parse(self) -> None:
        """
        Parse policy data to populate the policy's attributes.
        """
        ### Parse protocols
        for protocol_name in self.profile_data["protocols"]:
            try:
                profile_protocol = self.profile_data["protocols"][protocol_name]
                protocol = Protocol.init_protocol(protocol_name, profile_protocol, self.device)
            except ModuleNotFoundError:
                logger.warning(f"Protocol {protocol_name} not found.")
                # Unsupported protocol, skip it
                continue
            else:
                # Protocol is supported, parse it

                # Add custom parser if needed
                if protocol.custom_parser:
                    self.custom_parser = protocol_name
                
                ### Check involved devices
                protocols = ["arp", "ipv4", "ipv6"]
                # This device's addresses
                addrs = ["mac", "ipv4", "ipv6"]
                self_addrs = ["self"]
                for addr in addrs:
                    device_addr = self.device.get(addr, None)
                    if device_addr is not None:
                        self_addrs.append(device_addr)
                if protocol_name in protocols:
                    src = profile_protocol.get("spa", None) if protocol_name == "arp" else profile_protocol.get("src", None)
                    dst = profile_protocol.get("tpa", None) if protocol_name == "arp" else profile_protocol.get("dst", None)
                    
                    # Check if device is involved
                    if src in self_addrs or dst in self_addrs:
                        self.is_device = True


                # Add nft rules
                new_rules = protocol.parse(is_backward=self.is_backward, initiator=self.initiator)
                self.nft_matches += new_rules["nft"]

                # Add nfqueue matches
                for match in new_rules["nfq"]:
                    self.nfq_matches.append(match)


        ### Parse statistics
        if "stats" in self.profile_data:
            for stat in self.profile_data["stats"]:
                if stat in Policy.stats_metadata:
                    self.parse_stat(stat)


    def __eq__(self, other: object) -> bool:
        """
        Check whether this Policy object is equal to another object.

        :param other: object to compare to this Policy object
        :return: True if the other object represents the same policy, False otherwise
        """
        if not isinstance(other, self.__class__):
            return NotImplemented
        # Other object is a Policy object
        key_func = lambda x: x["template"].format(x["match"])
        self_matches = sorted(self.nft_matches, key=key_func)
        other_matches = sorted(other.nft_matches, key=key_func)
        return ( other.name == self.name and
                 other.is_backward == self.is_backward and
                 self.device == other.device and
                 self_matches == other_matches and
                 self.nft_stats == other.nft_stats and
                 self.nft_action == other.nft_action and
                 self.queue_num == other.queue_num )


    def __lt__(self, other: object) -> bool:
        """
        Check whether this Policy object is less than another object.

        :param other: object to compare to this Policy object
        :return: True if this Policy object is less than the other object, False otherwise
        """
        if not isinstance(other, self.__class__):
            return NotImplemented
        # Other object is a Policy object
        if self.queue_num >= 0 and other.queue_num >= 0:
            return self.queue_num < other.queue_num
        elif self.queue_num < 0:
            return False
        elif other.queue_num < 0:
            return True
        else:
            return self.name < other.name


    def __hash__(self) -> int:
        """
        Compute a hash value for this Policy object.

        :return: hash value for this Policy object
        """
        return hash((self.name, self.is_backward))


    @staticmethod
    def get_field_static(var: any, field: str, parent_key: str = "") -> Tuple[any, any]:
        """
        Retrieve the parent key and value for a given field in a dict.
        Adapted from https://stackoverflow.com/questions/9807634/find-all-occurrences-of-a-key-in-nested-dictionaries-and-lists.

        :param var: Data structure to search in
        :param field: Field to retrieve
        :param parent_key: Parent key of the current data structure
        :return: tuple containing the parent key and the value for the given field,
                 or None if the field is not found
        """
        if hasattr(var, 'items'):
            for k, v in var.items():
                if k == field:
                    return parent_key, v
                if isinstance(v, dict):
                    result = Policy.get_field_static(v, field, k)
                    if result is not None:
                        return result
                elif isinstance(v, list):
                    for d in v:
                        result = Policy.get_field_static(d, field, k)
                        if result is not None:
                            return result
        return None
    

    def get_field(self, field: str) -> Tuple[any, any]:
        """
        Retrieve the value for a given field in the policy profile data.
        Adapted from https://stackoverflow.com/questions/9807634/find-all-occurrences-of-a-key-in-nested-dictionaries-and-lists.

        :param field: Field to retrieve
        :return: tuple containing the parent key and the value for the given field,
                 or None if the field is not found
        """
        return Policy.get_field_static(self.profile_data, field, self.name)

    
    def parse_stat(self, stat: str) -> Dict[str, str]:
        """
        Parse a single statistic.
        Add the corresponding counters and nftables matches.

        :param stat: Statistic to handle
        :return: parsed stat, with the form {"template": ..., "match": ...}
        """
        parsed_stat = None
        value = self.profile_data["stats"][stat]
        if type(value) == dict:
            # Stat is a dictionary, and contains data for directions "fwd" and "bwd"
            value_fwd = Policy.parse_duration(value["fwd"]) if stat == "duration" else value["fwd"]
            value_bwd = Policy.parse_duration(value["bwd"]) if stat == "duration" else value["bwd"]
            if Policy.stats_metadata[stat]["counter"]:
                # Add counters for "fwd" and "bwd" directions
                self.counters[stat] = {
                    "fwd": value_fwd,
                    "bwd": value_bwd
                }
            if stat in Policy.stats_metadata and "template" in Policy.stats_metadata[stat]:
                parsed_stat = {
                    "template": Policy.stats_metadata[stat]["template"],
                    "match": value_bwd if self.is_backward else value_fwd,
                }
        else:
            # Stat is a single value, which is used for both directions
            if Policy.stats_metadata[stat]["counter"]:
                value = Policy.parse_duration(value) if stat == "duration" else value
                self.counters[stat] = {"default": value}
                value = f"\"{self.name[:-len('-backward')] if self.is_backward else self.name}\""
            if stat in Policy.stats_metadata and "template" in Policy.stats_metadata[stat]:
                parsed_stat = {
                    "template": Policy.stats_metadata[stat]["template"],
                    "match": value
                }
        
        if parsed_stat is not None and "nft_type" in Policy.stats_metadata[stat]:
            self.nft_stats[stat] = parsed_stat

    
    def build_nft_rule(self, queue_num: int, drop_proba: float = 1.0, log_type: LogType = LogType.NONE, log_group: int = 100) -> str:
        """
        Build and store the nftables match and action, as strings, for this policy.

        :param queue_num: number of the nfqueue queue corresponding to this policy,
                          or a negative number if the policy is simply `drop`
        :param rate: rate limit, in packets/second, for this policy
        :param log_type: type of logging to enable
        :param log_group: log group number
        :return: complete nftables rule for this policy
        """
        self.queue_num = queue_num

        # nftables match
        for i in range(len(self.nft_matches)):
            if i > 0:
                self.nft_match += " "
            template = self.nft_matches[i]["template"]
            data = self.nft_matches[i]["match"]
            self.nft_match += template.format(*(data)) if type(data) == list else template.format(data)

        # nftables stats
        for stat in self.nft_stats:
            template = self.nft_stats[stat]["template"]
            data = self.nft_stats[stat]["match"]
            if Policy.stats_metadata[stat].get("nft_type", 0) == Policy.NftType.MATCH:
                self.nft_match += " " + (template.format(*(data)) if type(data) == list else template.format(data))
            elif Policy.stats_metadata[stat].get("nft_type", 0) == Policy.NftType.ACTION:
                if self.nft_action:
                    self.nft_action += " "
                self.nft_action += (template.format(*(data)) if type(data) == list else template.format(data))

        ## nftables action
        if self.nft_action:
            self.nft_action += " "

        # Log action
        verdict = ""
        if queue_num >= 0:
            verdict = "QUEUE"
        elif drop_proba == 1.0:
            verdict = "DROP"
        elif drop_proba == 0.0:
            verdict = "ACCEPT"
        if log_type == LogType.CSV:
            self.nft_action += f"log prefix \\\"{self.name},,{verdict}\\\" group {log_group} "
        elif log_type == LogType.PCAP:
            self.nft_action += f"log group {log_group} "
        
        # Verdict action
        if queue_num >= 0:
            self.nft_action += f"queue num {queue_num}"
        elif drop_proba == 1.0:
            self.nft_action += "drop"
        elif drop_proba == 0.0:
            self.nft_action += "accept"

        return self.get_nft_rule()

    
    def get_nft_rule(self) -> str:
        """
        Retrieve the complete nftables rule, composed of the complete nftables match
        and the action, for this policy.

        :return: complete nftables rule for this policy
        """
        return f"{self.nft_match} {self.nft_action}"

    
    def get_domain_name_hosts(self) -> Tuple[str, dict]:
        """
        Retrieve the domain names and IP addresses for this policy, if any.

        :return: tuple containing:
                    - the IP family nftables match (`ip` or `ip6`)
                    - a dictionary containing a mapping between the direction matches (`saddr` or `daddr`)
                      and the corresponding domain names or list of IP addresses
        """
        result = {}
        directions = {
            "src": "daddr" if self.is_backward else "saddr",
            "dst": "saddr" if self.is_backward else "daddr"
        }
        protocol = "ipv4"
        for dir, match in directions.items():
            field = self.get_field(dir)
            if field is None:
                # Field is not present in the policy
                continue

            protocol, addr = self.get_field(dir)
            if not ip.is_ip_static(addr, protocol):
                # Host is a domain name, or
                # list of hosts includes domain names
                if type(addr) is list:
                    # Field is a list of hosts
                    for host in addr:
                        if ip.is_ip_static(host, protocol):
                            # Host is an explicit or well-known address
                            if match not in result:
                                result[match] = {}
                            result[match]["ip_addresses"] = result[match].get("ip_addresses", []) + [host]
                        else:
                            # Address is not explicit or well-known, might be a domain name
                            if match not in result:
                                result[match] = {}
                            result[match]["domain_names"] = result[match].get("domain_names", []) + [host]
                else:
                    # Field is a single host
                    if match not in result:
                        result[match] = {}
                    result[match]["domain_names"] = result[match].get("domain_names", []) + [addr]
        protocol = "ip" if protocol == "ipv4" else "ip6"
        return protocol, result


    def is_base_for_counter(self, counter: str):
        """
        Check if the policy is the base policy for a given counter.

        :param counter: Counter to check (packet-count or duration)
        :return: True if the policy is the base policy for the given counter and direction, False otherwise
        """
        if counter not in self.counters:
            return False

        # Counter is present for this policy
        direction = "bwd" if self.is_backward else "fwd"
        return ( ("default" in self.counters[counter] and not self.is_backward) or
                  direction in self.counters[counter] )
    

    def is_backward_for_counter(self, counter: str):
        """
        Check if the policy is the backward policy for a given counter.

        :param counter: Counter to check (packet-count or duration)
        :return: True if the policy is the backward policy for the given counter and direction, False otherwise
        """
        if counter not in self.counters:
            return False
        
        # Counter is present for this policy
        return "default" in self.counters[counter] and self.is_backward
    

    def get_data_from_nfqueues(self, nfqueues: list) -> dict:
        """
        Retrieve the policy dictionary from the nfqueue list.

        :param nfqueues: List of nfqueues
        :return: dictionary containing the policy data,
                 or None if the policy is not found
        """
        for nfqueue in nfqueues:
            for policy_dict in nfqueue.policies:
                if policy_dict["policy"] == self:
                    return policy_dict
        return None
    

    def get_nft_match_stats(self) -> dict:
        """
        Retrieve this policy's stats which correspond to an NFTables match.

        :return: dictionary containing the policy match statistics
        """
        result = {}
        for stat, data in self.nft_stats.items():
            if Policy.stats_metadata.get(stat, {}).get("nft_type", None) == Policy.NftType.MATCH:
                result[stat] = data
        return result


    def get_name(self) -> str:
        """
        Generate an identifier for this Policy.

        Returns:
            str: Identifier for this Policy.
        """
        profile_data_protocols: dict = self.profile_data["protocols"]
        protocols = profile_data_protocols.keys()
        id = ""

        for protocol in protocols:
            if id:
                id += "_"
            id += protocol
            protocol_data: dict = profile_data_protocols[protocol]
            for key, value in protocol_data.items():
                id += f"_{key}_{value}"

        return id
