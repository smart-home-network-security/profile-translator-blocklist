"""
Translate a device YAML profile to the corresponding pair
of NFTables firewall script and NFQueue C source code.
"""

## Imports
# Libraries
import os
import importlib
import yaml
import jinja2
from typing import Tuple
# Custom modules
from .arg_types import uint16, proba, directory
from .LogType import LogType
from .Policy import Policy
from .NFQueue import NFQueue
from pyyaml_loaders import IncludeLoader

# Package name
package = importlib.import_module(__name__).__name__.rpartition(".")[0]


##### Custom Jinja2 filters #####

def is_list(value: any) -> bool:
    """
    Custom filter for Jinja2, to check whether a value is a list.

    :param value: value to check
    :return: True if value is a list, False otherwise
    """
    return isinstance(value, list)


def debug(value: any) -> str:
    """
    Custom filter for Jinja2, to print a value.

    :param value: value to print
    :return: an empty string
    """
    print(str(value))
    return ""


##### Utility functions #####

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


def parse_policy(policy_data: dict, nfqueue_id: int, global_accs: dict, rate: int = None, drop_proba: float = 1.0,  log_type: LogType = LogType.NONE, log_group: int = 100) -> Tuple[Policy, bool]:
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


def translate_profile(
        profile_path: str,
        nfqueue_name: str     = None,
        nfqueue_id:   int     = 0,
        output_dir:   str     = None,
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

    ### INIT ###
    
    ## Argument validation
    # Retrieve device profile's path
    device_path = os.path.abspath(os.path.dirname(profile_path))
    if output_dir is None:
        output_dir = device_path
    # Validate NFQueue ID
    nfqueue_id = uint16(nfqueue_id)
    # Validate output directory
    output_dir = directory(output_dir)
    # Verify verdict mode
    if rate is not None and drop_proba is not None:
        raise ValueError("Arguments rate and drop_proba are mutually exclusive")
    # Validate drop probability
    if drop_proba is not None:
        drop_proba = proba(drop_proba)
    else:
        drop_proba = 1.0
    

    ## Jinja2 config
    loader = jinja2.PackageLoader(package, "templates")
    env = jinja2.Environment(loader=loader, trim_blocks=True, lstrip_blocks=True)
    # Add custom Jinja2 filters
    env.filters["debug"] = debug
    env.filters["is_list"] = is_list
    env.filters["any"] = any
    env.filters["all"] = all


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
            policy, new_nfq = parse_policy(policy_data, nfqueue_id, global_accs, rate, drop_proba, log_type, log_group)

            # Parse policy in backward direction, if needed
            if is_backward:
                policy_data_backward = {
                    "profile_data": profile_data,
                    "device": device,
                    "policy_name": f"{policy_name}-backward",
                    "is_backward": True
                }
                policy_backward, new_nfq = parse_policy(policy_data_backward, nfqueue_id + 1, global_accs, rate, drop_proba, log_type, log_group)

            # Update nfqueue variables if needed
            if new_nfq:
                nfqueue_id += nfq_id_inc


    ### OUTPUT ###

    # Create nftables script
    nft_dict = {
        "device": device,
        "nfqueues": global_accs["nfqueues"],
        "drop_proba": drop_proba,
        "log_type": log_type,
        "log_group": log_group,
        "test": test
    }
    env.get_template("firewall.nft.j2").stream(nft_dict).dump(os.path.join(output_dir, "firewall.nft"))

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
        header = env.get_template("header.c.j2").render(header_dict)
        callback_dict = {
            "nft_table": f"bridge {device['name']}",
            "nfqueues": global_accs["nfqueues"],
            "drop_proba": drop_proba
        }
        callback = env.get_template("callback.c.j2").render(callback_dict)
        main_dict = {
            "custom_parsers": global_accs["custom_parsers"],
            "nfqueues": global_accs["nfqueues"],
            "domain_names": global_accs["domain_names"],
            "num_threads": num_threads
        }
        main = env.get_template("main.c.j2").render(main_dict)

        # Write policy C file
        with open(os.path.join(output_dir, "nfqueues.c"), "w+") as fw:
            fw.write(header)
            fw.write(callback)
            fw.write(main)

        # Create CMake file
        custom_parsers = " ".join(global_accs["custom_parsers"])
        cmake_dict = {
            "device":  device["name"],
            "nfqueue_name": nfqueue_name,
            "custom_parsers": custom_parsers
        }
        env.get_template("CMakeLists.txt.j2").stream(cmake_dict).dump(os.path.join(output_dir, "CMakeLists.txt"))


    print(f"Done translating {profile_path}.")
