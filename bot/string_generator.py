import logging
from datetime import datetime
from typing import Optional, List, Tuple
import string
import os


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(process)d - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("string_generator")

CHARSET = string.ascii_lowercase + string.digits
OUTPUT_DIR = "dir"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def seed(magic: int, time: Optional[datetime] = None) -> int:
    logger.info(f"Generating seed with magic number: {magic} and time: {time}")
    if time:
        secs = time.second
        month = time.month - 1
        year = time.year
    else:
        secs = 32
        month = 13
        year = 1899
    result_seed = magic + (secs | ((month + 256) << 8)) + year
    logger.info(f"Generated seed: {result_seed}")
    return result_seed

def rand(r: int) -> int:
    r = r * 1664525 + 1013904223
    r &= (2**64 - 1)  # Keep within 64-bit
    for _ in range(32):
        if r & 1:
            r = (r // 2) ^ 0xF5000000
        else:
            r = r // 2
    return r

def sga(seed_value: int, length: int = 100, count: int = 10) -> List[str]:
    r = seed_value
    base_strings = []
    for _ in range(count):
        base_string = ""
        for _ in range(length):
            r = rand(r)
            base_string += CHARSET[r % len(CHARSET)]
        base_strings.append(base_string)
    return base_strings

def write_strings_to_file(filename: str, strings: List[str]) -> None:
    try:
        with open(filename, 'w') as file:
            for string in strings:
                file.write(string + '\n')
    except Exception as e:
        logger.error(f"Failed to write strings to {filename}: {e}")
        raise

def generate_and_split_base_strings(magic_seed: str):
    magic_value = sum(ord(v) << i * 8 for i, v in enumerate(magic_seed))
    base_strings_set = sga(magic_value)
    halfway_point = len(base_strings_set) // 2
    command_strings_subset = base_strings_set[:halfway_point]
    status_strings_subset = base_strings_set[halfway_point:]
    logger.info(f"command_strings_subset: {command_strings_subset}")
    logger.info(f"status_strings_subset: {status_strings_subset}")
    return command_strings_subset, status_strings_subset

def generate_cipher_base_strings(magic_seed: str) -> list[str]:
    magic_value = sum(ord(v) << i * 8 for i, v in enumerate(magic_seed))
    logger.info(f"Computed magic value: {magic_value}")
    base_strings = sga(magic_value)
    logger.info(f"Base strings genereated: {base_strings}")
    return base_strings
