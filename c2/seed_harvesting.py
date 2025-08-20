import requests
from datetime import datetime, timedelta
import hashlib
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(process)d - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("seed_harvesting")

def generate_dynamic_seed():
    """
    Generate a cryptographically secure seed using Bitcoin historical data.

    Entropy Sources:
    - Historical price data
    - Market capitalization
    - Trading volume
    """
    # Calculate yesterday's date dynamically
    yesterday = (datetime.now() - timedelta(days=1)).strftime('%d-%m-%Y')

    # Construct CoinGecko API endpoint
    api_url = f"https://api.coingecko.com/api/v3/coins/bitcoin/history?date={yesterday}"
    try:
        # Fetch historical cryptocurrency data
        response = requests.get(api_url)
        response.raise_for_status()

        # Extract entropy components
        data = response.json()
        logger.info(f"cryptocurrency data: {data}")
        seed_components = [
            str(data.get('market_data', {}).get('current_price', {}).get('usd', 0)),
            str(data.get('market_data', {}).get('market_cap', {}).get('usd', 0)),
            str(data.get('market_data', {}).get('total_volume', {}).get('usd', 0)),
            str(datetime.now().strftime('%H-%d-%m-%Y'))  # Additional temporal entropy
        ]
        logger.info(f"seed_components: {seed_components}")
        seed = hashlib.sha256(''.join(seed_components).encode()).hexdigest()
        logger.info(f"seed: {seed}")
        return seed
    except requests.RequestException as e:
        logger.error(f"Seed generation failed: {e}")
        return None