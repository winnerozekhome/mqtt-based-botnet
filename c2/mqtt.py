
from cipher import decrypt
import paho.mqtt.client as mqtt2
from paho.mqtt import MQTTException
import time
import json
import hashlib
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(process)d - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("mqtt")

CONFIG = {
    'max_retries': 5,
    'retry_delay': 1,
    'time_out': 20,
    'id': "MASTER",
}

def on_subscribe(client, userdata, mid, reason_code_list, properties):
    logger.info(f"Subscription Acknowledgment - Reason Codes: {reason_code_list}")
    if isinstance(reason_code_list, list) and len(reason_code_list) == 0:
        logger.error("Error: Empty subscription response! Broker may not support MQTT v5.")
    elif any(code >= 128 for code in reason_code_list):
        logger.error("Error: Subscription was rejected by the broker.")
    elif reason_code_list[0].is_failure:
        logger.error(f"{userdata['broker']} rejected subscription: {reason_code_list[0]}")
    else:
        logger.info(f"{userdata['broker']} granted QoS: {reason_code_list[0].value}")


def on_unsubscribe(client, userdata, mid, reason_code_list, properties):
    if len(reason_code_list) == 0 or not reason_code_list[0].is_failure:
        logger.info(f"{userdata['broker']}: Unsubscription succeeded.")
    else:
        logger.error(
            f"{userdata['broker']}: Broker replied with failure: {reason_code_list[0]}")


def on_disconnect(client, userdata, rc, properties, reason_code):
    logger.info(
        f"Disconnected from the broker: {userdata['broker']} with reason code: {reason_code}")


def on_publish(client, userdata, mid, reason_code=None, properties=None):
    logger.info(
        f"Message published on broker: {userdata['broker']} on topic:  {userdata['topic']}")


def on_message(client, userdata, message):
    topic = message.topic
    payload_str = message.payload.decode('utf-8')

    logger.info(
        f"{userdata['broker']}:{topic} Received encrypted message: {payload_str}")
    message_hash = hashlib.sha256(payload_str.encode()).hexdigest()
    if "processed_messages" not in userdata:
        userdata["processed_messages"] = {}
    processed_messages = userdata["processed_messages"]
    # Check if the message has already been processed
    if message_hash in processed_messages.get(topic, set()):
        logger.info(f"Duplicate message ignored for topic: {topic}")
        return  # Ignore duplicate message

    # Store the new hash to prevent future duplicates
    if topic not in processed_messages:
        processed_messages[topic] = set()
    processed_messages[topic].add(message_hash)
    cipher_keys = userdata['cipher_keys']
    cipher_key = cipher_keys.get(topic)

    if cipher_key:
        logger.info(f"{userdata['broker']}: cipher_key: {cipher_key}")
        decrypted_message = decrypt(cipher_key, payload_str)
        logger.info(f"{userdata['broker']}: Decrypted message: {decrypted_message}")
        message_processor(client, userdata, topic, decrypted_message)
    else:
        logger.warning(f"Received message on unrecognized topic: {topic}")

def subscribe_multitopics_on_broker(broker, topics, cipher_keys, client_id, token):
    mqttc = mqtt2.Client(mqtt2.CallbackAPIVersion.VERSION2)  # Using MQTTv5
    mqttc.on_connect = on_connect
    mqttc.on_message = on_message
    mqttc.on_subscribe = on_subscribe
    mqttc.on_unsubscribe = on_unsubscribe
    userdata = {
        'token': token,
        'topics': topics,
        'cipher_keys': cipher_keys,
        'broker': broker,
        'messages': [],
        'target': "subscribe",
        'retry_count': 0,
        'connected': False,
        'client_id': client_id
    }

    mqttc.user_data_set(userdata)
    retry_count = 0
    connected = False

    logger.info(f"{client_id}:{broker}: Connecting to broker: {broker}")
    while not connected and retry_count < CONFIG['max_retries']:
        try:
            mqttc.connect(broker)
            connected = True  # Connection successful
        except TimeoutError:
            retry_count += 1
            logger.info(f"{client_id}:{broker}: TimeoutError: Retry {retry_count}/{CONFIG['max_retries']}")
            time.sleep(CONFIG['retry_delay'])  # Wait before retrying
        except MQTTException as e:
            logger.info(f"{client_id}:{broker}: MQTTException: {e}")
            break

    if connected:
        logger.info(f"{client_id}:{broker}:Connection successful. Starting loop to subscribe...")
        try:
            mqttc.loop_forever()  # Blocking loop for subscription
        except KeyboardInterrupt:
            logger.info(f"{client_id}:{broker}: Interrupted. Disconnecting from broker...")
            mqttc.disconnect()
    else:
        logger.info(f"{client_id}:{broker}:Failed to connect to broker after {CONFIG['max_retries']} retries.")


def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code.is_failure:
        logger.error(f"{userdata['broker']}: Failed to connect {userdata['retry_count']}/5: {reason_code}")
        retry_count = userdata['retry_count']
        if retry_count >= CONFIG['max_retries']:
            logger.error(f"{userdata['broker']}: Maximum retries reached. Disconnecting.")
            userdata['max_retries_reached'] = True  # Set a flag to indicate max retries reached
            client.loop_stop()
            client.disconnect()
            return False
        userdata['retry_count'] += 1
    else:
        if userdata['target'] == "subscribe":
            logger.info(f"{userdata['broker']}: Connected for subscription.")
            for topic in userdata['topics']:
                client.subscribe(topic)
                logger.info(f"{userdata['broker']}: Subscribed to topic: {topic}")
        else:
            logger.info(f"{userdata['broker']}: Connected for publishing.")
            userdata['connected'] = True  # Set connected flag to True on successful connect


def publish_on_broker(broker, topic, encrypted_message, token):
    client = mqtt2.Client(mqtt2.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_publish = on_publish
    userdata = {
        'token': token,
        'broker': broker,
        'topic': topic,
        'encrypted_message': encrypted_message,
        'target': "publish",
        'retry_count': 0,
        'connected': False,
        'client_id': broker,
        'max_retries_reached': False  # Add flag to track if max retries was reached
    }
    client.user_data_set(userdata)
    logger.info(f"{broker}: Connecting... to broker")

    try:
        client.socket_timeout = CONFIG['time_out']
        client.connect_async(broker)  # Use connect_async instead of connect
        client.loop_start()  # Start the network loop

        # Wait for either connection success or max retries
        wait_start = time.time()
        total_wait_time = CONFIG['time_out'] + 5
        while not userdata['connected'] and not userdata['max_retries_reached']:
            if time.time() - wait_start > total_wait_time:
                logger.error(f"{broker}: Connection attempt timed out")
                break
            time.sleep(0.1)
        if userdata['max_retries_reached']:
            logger.error(f"{broker}: Maximum retries reached during connection")
            return False

        if not userdata['connected']:
            logger.error(f"{broker}: Failed to connect to broker {broker}")
            return False
        logger.info(f"{broker}: Connected successfully.")
        try:
            logger.info(f"{broker}: Publishing message...")
            msg_info = client.publish(userdata['topic'], userdata['encrypted_message'], qos=1, retain=True)
            start_time = time.time()
            while not msg_info.is_published():
                if time.time() - start_time > CONFIG['time_out']:
                    logger.warning(
                        f"{broker}: Publish did not complete within {CONFIG['time_out']} seconds.")
                    return False
                time.sleep(0.1)
            logger.info(f"{broker}: Publish completed successfully.")
            return True

        except RuntimeError as e:
            logger.error(f"{broker}: Message publish failed: {e}")
            return False
        except MQTTException as e:
            logger.error(f"{broker}: MQTT error during publish: {e}")
            return False
    except Exception as e:
        logger.error(f"{broker}: Connection error: {e}")
        return False
    finally:
        client.loop_stop()
        client.disconnect()

def message_processor(client, userdata, topic, decrypted_message):
    try:
        data = json.loads(decrypted_message)
        type = data.get("type", "")
        match type:
            case "SYNC":
                logger.info(f"{userdata['broker']}: SYNC ok")
                return
            case "SYNACK":
                logger.info(f"{userdata['broker']}: SYNACK ok")
                return
            case "CMD_ACK":
                logger.info(f"{userdata['broker']}: CMD_ACK ok")
                return
            case "status":
                logger.info(f"{userdata['broker']}: status ok")
                return
            case _:
                logging.error("ERROR")
                return "Unknown Status"
    except json.JSONDecodeError as e:
        logging.error(f"JSON parsing error: {e}")