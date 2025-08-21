"""
Translate a device YAML profile to the corresponding pair
of NFTables firewall script and NFQueue C source code.
"""

## Imports
# Libraries
from typing import Iterable
import os
import importlib
import re
import yaml
from typing import Tuple
# Custom modules
from .arg_types import uint16, proba, directory
from .jinja_utils import create_jinja_env
from .LogType import LogType
from .Policy import Policy
from .NFQueue import NFQueue
from pyyaml_loaders import IncludeLoader

# Package name
module_relative_path = importlib.import_module(__name__).__name__
package = module_relative_path.rpartition(".")[0]

# Logging
import logging
logger = logging.getLogger(module_relative_path)


##### FUNCTIONS #####

def slugify_name(name: str) -> str:
    """
    Slugify a (NFQueue) name by replacing all non-alphanumeric characters with underscores.

    :param name: name to slugify
    :return: slugified name
    """
    pattern = r"[^a-zA-Z0-9_]"
    special_chars = re.findall(pattern, name)
    for char in special_chars:
        name = name.replace(char, "_")
    return name


def flatten_policies(single_policy_name: str, single_policy: dict, acc: dict = {}) -> None:
    """
    Flatten a nested single policy into a list of single policies.

    :param single_policy_name: Name of the single policy to be flattened
    :param single_policy: Single policy to be flattened
    :param acc: Accumulator for the flattened policies
    """
    if "protocols" in single_policy:
        acc[single_policy_name] = single_policy
        if single_policy.get("bidirectional", False):
            acc[f"{single_policy_name}-backward"] = single_policy
    else:
        for subpolicy in single_policy:
            flatten_policies(subpolicy, single_policy[subpolicy], acc)


def parse_policy(
        policy_data: dict,
        global_accs: dict,
        nfqueue_id:  int     = 0,
        rate:        int     = None,
        drop_proba:  float   = 1.0,
        log_type:    LogType = LogType.NONE,
        log_group:   int     = 100
    ) -> Tuple[Policy, bool]:
    """
    Parse a policy.

    :param policy_data: Dictionary containing all the necessary data to create a Policy object
    :param global_accs: Dictionary containing the global accumulators
    :param rate: Rate limit, in packets/second, to apply to matched traffic
    :param drop_proba: Dropping probability, between 0 and 1, to apply to matched traffic
    :param log_type: Type of packet logging to be used
    :param log_group: Log group ID to be used
    :return: the parsed policy, as a `Policy` object, and a boolean indicating whether a new NFQueue was created
    """
    # If rate limit is given, add it to policy data
    if rate is not None:
        policy_data["profile_data"]["stats"] = {"rate": f"{rate}/second"}

    # Create and parse policy
    policy = Policy(**policy_data)

    # If policy has domain name match,
    # add domain name to global list
    _, hosts = policy.get_domain_name_hosts()
    for direction in ["saddr", "daddr"]:
        domain_names = hosts.get(direction, {}).get("domain_names", [])
        for name in domain_names:
            if name not in global_accs["domain_names"]:
                global_accs["domain_names"].append(name)
    
    # Add nftables rules
    not_nfq = not policy.nfq_matches and (drop_proba == 0.0 or drop_proba == 1.0)
    nfqueue_id = -1 if not_nfq else nfqueue_id
    policy.build_nft_rule(nfqueue_id, drop_proba, log_type, log_group)
    new_nfq = False
    try:
        # Check if nft match is already stored
        nfqueue = next(nfqueue for nfqueue in global_accs["nfqueues"] if nfqueue.contains_policy_matches(policy))
    except StopIteration:
        # No nfqueue with this nft match
        nfqueue = NFQueue(policy.name, policy.nft_matches, nfqueue_id)
        global_accs["nfqueues"].append(nfqueue)
        new_nfq = nfqueue_id != -1
    finally:
        nfqueue.add_policy(policy)
    
    # Add custom parser (if any)
    if policy.custom_parser:
        global_accs["custom_parsers"].add(policy.custom_parser)

    return policy, new_nfq


def validate_args(
        output_dir: str = os.getcwd(),
        nfqueue_id: int = 0,
        rate:       int = None,
        drop_proba: float = None,
    ) -> dict:
    """
    Validate arguments for the translation process.

    Args:
        output_dir (str): Output directory for the generated files
        nfqueue_id (int): NFQueue start index for this profile's policies (must be an integer between 0 and 65535)
        rate (int): Rate limit, in packets/second, to apply to matched traffic, instead of a binary verdict
        drop_proba (float): Dropping probability to apply to matched traffic, instead of a binary verdict
    Raises:
        ValueError: If rate and drop_proba are both provided
    """
    # Initialize result dictionary
    args = {}

    # Output directory: existing directory
    try:
        output_dir = directory(output_dir)
    except ValueError:
        logger.warning(f"Output directory {output_dir} does not exist. Using current directory.")
        output_dir = os.getcwd()
    args["output_dir"] = output_dir

    # NFQueue ID: integer between 0 and 65535
    nfqueue_id = uint16(nfqueue_id)
    args["nfqueue_id"] = nfqueue_id

    # Verdict mode: rate or drop_proba (mutually exclusive)
    if rate is not None and drop_proba is not None:
        raise ValueError("Arguments rate and drop_proba are mutually exclusive")
    args["rate"] = rate
 
    # Drop probability: float between 0 and 1
    if drop_proba is not None:
        drop_proba = proba(drop_proba)
    else:
        drop_proba = 1.0
    args["drop_proba"] = drop_proba

    return args


def write_firewall(
        device:       dict,
        global_accs:  dict,
        nfqueue_name: str     = None,
        output_dir:   str     = os.getcwd(),
        drop_proba:   float   = 1.0,
        log_type:     LogType = LogType.NONE,
        log_group:    int     = 100,
        test:         bool    = False
    ) -> None:
    """
    Write NFTables firewall script and NFQueue C source code with given parameters.

    Args:
        device (dict): Device metadata
        global_accs (dict): Global accumulators containing policy data
        nfqueue_name (str): Name of the device's NFQueue
        output_dir (str): Output directory for the generated files
        drop_proba (float): Dropping probability to apply to matched traffic, instead of a binary verdict
        log_type (LogType): Type of packet logging to be used
        log_group (int): Log group number (must be an integer between 0 and 65535)
        test (bool): Test mode: use VM instead of router
    """
    args = validate_args(output_dir=output_dir, drop_proba=drop_proba)
    drop_proba = args["drop_proba"]

    # Jinja2 environment
    templates = {}
    env = create_jinja_env(package)
    templates["firewall.nft"]   = env.get_template("firewall.nft.j2")
    templates["header.c"]       = env.get_template("header.c.j2")
    templates["callback.c"]     = env.get_template("callback.c.j2")
    templates["main.c"]         = env.get_template("main.c.j2")
    templates["CMakeLists.txt"] = env.get_template("CMakeLists.txt.j2")

    # Create nftables script
    nft_dict = {
        "device": device,
        "nfqueues": global_accs["nfqueues"],
        "drop_proba": drop_proba,
        "log_type": log_type,
        "log_group": log_group,
        "test": test
    }
    templates["firewall.nft"].stream(nft_dict).dump(os.path.join(output_dir, "firewall.nft"))

    # If needed, create NFQueue-related files
    num_threads = len([q for q in global_accs["nfqueues"] if q.queue_num >= 0])
    if num_threads > 0:
        # Create nfqueue C file by rendering Jinja2 templates
        header_dict = {
            "device": device["name"],
            "custom_parsers": global_accs["custom_parsers"],
            "domain_names": global_accs["domain_names"],
            "drop_proba": drop_proba,
            "num_threads": num_threads,
        }
        header = templates["header.c"].render(header_dict)
        callback_dict = {
            "nft_table": f"bridge {device['name']}",
            "nfqueues": global_accs["nfqueues"],
            "drop_proba": drop_proba
        }
        callback = templates["callback.c"].render(callback_dict)
        main_dict = {
            "custom_parsers": global_accs["custom_parsers"],
            "nfqueues": global_accs["nfqueues"],
            "domain_names": global_accs["domain_names"],
            "num_threads": num_threads
        }
        main = templates["main.c"].render(main_dict)

        # Write policy C file
        with open(os.path.join(output_dir, "nfqueues.c"), "w+") as fw:
            fw.write(header)
            fw.write(callback)
            fw.write(main)

        # Create CMake file
        cmake_dict = {
            "device":  device["name"],
            "nfqueue_name": slugify_name(nfqueue_name),
            "custom_parsers": global_accs["custom_parsers"],
            "domain_names": global_accs["domain_names"]
        }
        templates["CMakeLists.txt"].stream(cmake_dict).dump(os.path.join(output_dir, "CMakeLists.txt"))


def translate_policy(
        device:       dict,
        policy_dict:  dict,
        nfqueue_name: str     = None,
        nfqueue_id:   int     = 0,
        output_dir:   str     = os.getcwd(),
        rate:         int     = None,
        drop_proba:   float   = None,
        log_type:     LogType = LogType.NONE,
        log_group:    int     = 100,
        test:         bool    = False
    ) -> None:
    """
    Translate a policy to the corresponding pair of NFTables firewall script and NFQueue C source code.

    Args:
        device (dict): Device metadata
        policy_dict (dict): Policy data
        nfqueue_id (int): NFQueue start index for this profile's policies (must be an integer between 0 and 65535)
        output_dir (str): Output directory for the generated files
        rate (int): Rate limit, in packets/second, to apply to matched traffic, instead of a binary verdict
        drop_proba (float): Dropping probability to apply to matched traffic, instead of a binary verdict
        log_type (LogType): Type of packet logging to be used
        log_group (int): Log group number (must be an integer between 0 and 65535)
        test (bool): Test mode: use VM instead of router
    """
    ## Argument validation
    args = validate_args(output_dir, nfqueue_id, rate, drop_proba)
    output_dir = args["output_dir"]
    drop_proba = args["drop_proba"]

    ## Prepare policy data
    policy_data = {
        "profile_data": policy_dict,
        "device": device
    }

    ## Parse policy
    global_accs = {
        "custom_parsers": set(),
        "nfqueues": [],
        "domain_names": []
    }
    policy, _ = parse_policy(policy_data, global_accs, nfqueue_id, rate, drop_proba, log_type, log_group)
    policy_name = policy.get_name()
    if policy_dict.get("bidirectional", False):
        policy_data_backward = {
            "profile_data": policy_dict,
            "device": device,
            "policy_name": f"{policy_name}-backward",
            "is_backward": True
        }
        parse_policy(policy_data_backward, global_accs, nfqueue_id + 1, rate, drop_proba, log_type, log_group)

    ## Output
    nfqueue_name = policy_name if nfqueue_name is None else nfqueue_name
    write_firewall(device, global_accs, nfqueue_name, output_dir, drop_proba, log_type, log_group, test)


def translate_policies(
        device:       dict,
        policies:     Iterable[dict],
        nfqueue_name: str     = None,
        nfqueue_id:   int     = 0,
        output_dir:   str     = os.getcwd(),
        rate:         int     = None,
        drop_proba:   float   = None,
        log_type:     LogType = LogType.NONE,
        log_group:    int     = 100,
        test:         bool    = False
) -> None:
    """
    Translate a list of policies to the corresponding pair of NFTables firewall script and NFQueue C source code.

    Args:
        device (dict): Device metadata
        policies (Iterable[dict]): iterable containing the policies to translate
        nfqueue_id (int): NFQueue start index for this profile's policies (must be an integer between 0 and 65535)
        output_dir (str): Output directory for the generated files
        rate (int): Rate limit, in packets/second, to apply to matched traffic, instead of a binary verdict
        drop_proba (float): Dropping probability to apply to matched traffic, instead of a binary verdict
        log_type (LogType): Type of packet logging to be used
        log_group (int): Log group number (must be an integer between 0 and 65535)
        test (bool): Test mode: use VM instead of router
    """
    # Argument validation
    args = validate_args(output_dir, nfqueue_id, rate, drop_proba)
    output_dir = args["output_dir"]
    drop_proba = args["drop_proba"]

    # Initialize loop variables
    nfq_id_inc = 10
    global_accs = {
        "custom_parsers": set(),
        "nfqueues": [],
        "domain_names": []
    }

    # Loop over given policies
    for policy_dict in policies:

        # Forward
        policy_data = {
            "profile_data": policy_dict,
            "device": device
        }
        policy, new_nfq_fwd = parse_policy(policy_data, global_accs, nfqueue_id, rate, drop_proba, log_type, log_group)
        policy_name = policy.get_name()

        # Backward
        if policy_dict.get("bidirectional", False):
            policy_data_backward = {
                "profile_data": policy_dict,
                "device": device,
                "policy_name": f"{policy_name}-backward",
                "is_backward": True
            }
            _, new_nfq_bwd = parse_policy(policy_data_backward, global_accs, nfqueue_id + 1, rate, drop_proba, log_type, log_group)

        # Increment nfqueue_id if needed
        if new_nfq_fwd or new_nfq_bwd:
            nfqueue_id += nfq_id_inc
    
    # Output
    nfqueue_name = device.get("name", policy_name) if nfqueue_name is None else nfqueue_name
    write_firewall(device, global_accs, nfqueue_name, output_dir, drop_proba, log_type, log_group, test)


def translate_profile(
        profile_path: str,
        nfqueue_name: str     = None,
        nfqueue_id:   int     = 0,
        output_dir:   str     = os.getcwd(),
        rate:         int     = None,
        drop_proba:   float   = None,
        log_type:     LogType = LogType.NONE,
        log_group:    int     = 100,
        test:         bool    = False
    ) -> None:
    """
    Translate a device YAML profile to the corresponding pair of NFTables firewall script and NFQueue C source code.

    Args:
        profile_path (str): Path to the device YAML profile
        nfqueue_name (str): Name of the device's NFQueue
        nfqueue_id (int): NFQueue start index for this profile's policies (must be an integer between 0 and 65535)
        output_dir (str): Output directory for the generated files
        rate (int): Rate limit, in packets/second, to apply to matched traffic, instead of a binary verdict
        drop_proba (float): Dropping probability to apply to matched traffic, instead of a binary verdict
        log_type (LogType): Type of packet logging to be used
        log_group (int): Log group number (must be an integer between 0 and 65535)
        test (bool): Test mode: use VM instead of router
    """
    # Retrieve device profile's path
    device_path = os.path.abspath(os.path.dirname(profile_path))
    if output_dir is None:
        output_dir = device_path
    # Argument validation
    args = validate_args(output_dir, nfqueue_id, rate, drop_proba)
    output_dir = args["output_dir"]
    nfqueue_id = args["nfqueue_id"]
    rate = args["rate"]
    drop_proba = args["drop_proba"]


    ### MAIN ###

    # NFQueue ID increment
    nfq_id_inc = 10

    # Load the device profile
    profile = {}
    with open(profile_path, "r") as f:
        # Load YAML profile with custom loader
        profile = yaml.load(f, IncludeLoader)

    # Get device info
    device = profile["device-info"]

    # Set device's NFQueue name if not provided as argument
    nfqueue_name = nfqueue_name if nfqueue_name is not None else device["name"]

    # Global accumulators
    global_accs = {
        "custom_parsers": set(),
        "nfqueues": [],
        "domain_names": []
    }


    ## Loop over the device's individual policies
    if "single-policies" in profile:
        for policy_name in profile["single-policies"]:
            profile_data = profile["single-policies"][policy_name]

            policy_data = {
                "profile_data": profile_data,
                "device": device,
                "policy_name": policy_name,
                "is_backward": False
            }
            
            # Parse policy
            is_backward = profile_data.get("bidirectional", False)
            _, new_nfq_fwd = parse_policy(policy_data, global_accs, nfqueue_id, rate, drop_proba, log_type, log_group)

            # Parse policy in backward direction, if needed
            if is_backward:
                policy_data_backward = {
                    "profile_data": profile_data,
                    "device": device,
                    "policy_name": f"{policy_name}-backward",
                    "is_backward": True
                }
                _, new_nfq_bwd = parse_policy(policy_data_backward, global_accs, nfqueue_id + 1, rate, drop_proba, log_type, log_group)

            # Update nfqueue variables if needed
            if new_nfq_fwd or new_nfq_bwd:
                nfqueue_id += nfq_id_inc


    ### OUTPUT ###

    write_firewall(device, global_accs, nfqueue_name, output_dir, drop_proba, log_type, log_group, test)

    logger.info(f"Done translating {profile_path}.")
