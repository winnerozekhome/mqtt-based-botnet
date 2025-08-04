import argparse
import signal

from seed_harvesting import generate_dynamic_seed
from bot import *

BASE_DIR = "dir"
os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs("dir/seeds/", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(process)d - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("main")
current_process = None


def load_file(filename, bot_id=None):
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f.readlines()]
    except FileNotFoundError as e:
        logger.error(f"{log_context(bot_id)} File not found: {filename}. Error: {e}")
        return []

def kill_current_process():
    global current_process
    if current_process is not None and current_process.is_alive():
        logger.info(f"Terminating previous TGA process (PID: {current_process.pid})")

        try:
            # Try graceful termination first
            current_process.terminate()
            current_process.join(timeout=5)

            # If still alive, force kill
            if current_process.is_alive():
                logger.warning("Process didn't terminate gracefully, using SIGKILL")
                kill_process_tree(current_process.pid)

            logger.info("Previous TGA process terminated")
        except Exception as e:
            logger.error(f"Error while terminating process: {e}")

    # Reset the current process
    current_process = None


def kill_process_tree(pid):
    """Kill a process and all its children recursively"""
    try:
        import psutil
        parent = psutil.Process(pid)
        for child in parent.children(recursive=True):
            try:
                child.terminate()
            except:
                pass

        # Give them time to terminate
        psutil.wait_procs(parent.children(recursive=True), timeout=3)

        # If any still alive, force kill
        for child in parent.children(recursive=True):
            try:
                child.kill()
            except:
                pass
        parent.kill()
    except Exception as e:
        logger.error(f"Error killing process tree: {e}")
        # Fallback to traditional SIGKILL
        try:
            os.kill(pid, signal.SIGKILL)
        except:
            pass


def init_bot(instance_number):
    global current_process
    # First, kill any existing process
    kill_current_process()
    bot_id = instance_number
    logger.info(f"Starting bot instance: {bot_id}")
    while True:
        seed = generate_dynamic_seed()
        if seed:
            break
        else:
            wait_time = random.randint(5, 30) # to be set in config file
            logger.info(f"Waiting for seed... Retrying in {wait_time} seconds.")
            time.sleep(wait_time)
    logger.info(f"seed: {seed}")
    seed_file = f"dir/seeds/{bot_id}___{seed}.txt"
    with open(seed_file, 'w') as f:
        f.write(seed + '\n')
    brokers_file = os.path.join(BASE_DIR, "public_mqtt_brokers.txt")
    base_brokers_set = load_file(brokers_file)
    current_process = threading.Thread(target=start_bot, args=(bot_id, base_brokers_set, seed))
    current_process.daemon = False
    current_process.start()


def start_bot(bot_id, base_brokers_set, seed):
    tga_bot = Bot(bot_id, seed)
    tga_bot.start(base_brokers_set)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MQTT Bot Script")
    parser.add_argument("--instance", type=int, help="Instance number of the script", required=True)
    args = parser.parse_args()
    instance_number = args.instance
    logger.info(f"Running instance number: {instance_number}")
    # Register signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        logger.info("Shutdown signal received, terminating...")
        kill_current_process()
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    init_bot(instance_number)
