
from typing import Optional, List, Tuple
import string
import os

import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(process)d - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("string_generator")
# Constants
CHARSET = string.ascii_lowercase + string.digits
OUTPUT_DIR = "dir"

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

def rand(r: int) -> int:
    """
    Pseudo-random number generator based on a specific algorithm.
    """
    r = r * 1664525 + 1013904223
    r &= (2**64 - 1)
    for _ in range(32):
        if r & 1:
            r = (r // 2) ^ 0xF5000000
        else:
            r = r // 2
    return r

def sga(seed_value: int, length: int = 100, count: int = 10) -> List[str]:
    """
    Generates a list of pseudo-random base strings based on the seed value.
    """
    r = seed_value
    base_strings = []
    for _ in range(count):
        base_string = ""
        for _ in range(length):
            r = rand(r)
            base_string += CHARSET[r % len(CHARSET)]
        base_strings.append(base_string)
    return base_strings

def generate_and_split_base_strings(seed: str):
    magic_value = sum(ord(v) << i * 8 for i, v in enumerate(seed))
    base_strings_set = sga(magic_value)
    halfway_point = len(base_strings_set) // 2
    command_strings_subset = base_strings_set[:halfway_point]
    status_strings_subset = base_strings_set[halfway_point:]
    logger.info(f"command_strings_subset: {command_strings_subset}")
    logger.info(f"status_strings_subset: {status_strings_subset}")
    return command_strings_subset, status_strings_subset
