import logging
from datetime import datetime
from typing import Optional, Generator
import string
import os

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(process)d - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("TGA-generator")

def log_context(bot_id=None, broker=None):
    """Generate contextual log prefix."""
    if bot_id and broker:
        return f"[{bot_id}::{broker}]"
    elif bot_id:
        return f"[{bot_id}]"
    elif broker:
        return f"[{broker}]"
    return ""


# Constants
CHARSET = string.ascii_lowercase + string.digits

def rand(r: int) -> int:
    r = r * 1664525 + 1013904223
    r &= (2 ** 64 - 1)  # Keep within 64-bit
    for _ in range(32):
        if r & 1:
            r = (r // 2) ^ 0xF5000000
        else:
            r = r // 2
    return r

def tga(seed: int, count: int = 1, length: int = 100) -> Generator[str, None, None]:
    r = seed
    for _ in range(count):
        topic = ""
        for _ in range(length):
            r = rand(r)
            topic += CHARSET[r % len(CHARSET)]
        yield topic

def write_topics_to_file(output_file: str, topics: Generator[str, None, None]) -> None:
    try:
        with open(output_file, 'w') as file:
            for topic in topics:
                file.write(topic + '\n')
    except Exception as e:
        logger.error(f"Failed to write topics to {output_file}: {e}")
        raise

def generate_topic(tga_seed, topic_length, topic_level) -> str:
    tga_seed_numeric_value = sum(ord(v) << i * 8 for i, v in enumerate(tga_seed))
    topic = next(tga(seed = tga_seed_numeric_value, length = topic_length))
    return generate_mqtt_topic(topic, topic_level)

def generate_mqtt_topic(input_string, levels):
    if levels <= 0:
        return input_string
    total_length = len(input_string)
    chars_per_level = total_length // levels

    topic_parts = []
    start_pos = 0
    for i in range(levels - 1):
        end_pos = start_pos + chars_per_level
        level_part = input_string[start_pos:end_pos]
        topic_parts.append(level_part)
        start_pos = end_pos
    last_part = input_string[start_pos:]
    topic_parts.append(last_part)
    mqtt_topic = f"/{'/'.join(topic_parts)}"
    return mqtt_topic