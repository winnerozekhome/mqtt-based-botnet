# MQTT-Based Botnet

A research-oriented implementation of a botnet architecture utilizing MQTT (Message Queuing Telemetry Transport) protocol for command and control (C2) communication.

## ⚠️ Disclaimer

**This project is intended for educational and research purposes only.** 
**DO NOT use this software for:**
- Unauthorized access to computer systems
- Any illegal activities
- Malicious attacks on networks or systems
- Any activities that violate local, state, or federal laws

The authors and contributors are not responsible for any misuse of this software.

## 📋 Overview

This project demonstrates a botnet architecture that uses MQTT as the communication protocol between the command and control (C2) server and infected clients (bots).

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client Bot 1  │    │   Client Bot 2  │    │   Relay Bot 1   │    │   Relay Bot 2   │
│                 │    │                 │    │                 │    │                 │
└─────────┬───────┘    └─────────┬───────┘    └─────┬───────┬───┘    └───┬─────────┬───┘
          │                      │                  │       │            │         │
          │                      │                  │       │            │         │
          │              ┌───────▼──────────────────▼───────┼────────────┼─────────┘
          │              │                                  │            │
          │              │                          ┌───────▼────────────▼───────┐
          │              │                          │                            │
      ┌───▼──────────────▼───┐                  ┌───▼──────────┐             ┌───▼──────────┐
      │   MQTT Broker 1      │                  │ MQTT Broker 2│             │ MQTT Broker N│
      │                      │                  │              │             │              │
      └───┬──────────────────┘                  └───┬──────────┘             └───┬──────────┘
          │                                         │                            │
          │                                         │                            │
          └─────────────────────┬───────────────────┼────────────────────────────┘
                                │                   │
                                │                   │
                    ┌───────────▼───────────────────▼────────────┐
                    │         C2 Controller                      │
                    │         Admin Interface                    │
                    └────────────────────────────────────────────┘

Legend:
- Client Bots: Connect to only ONE broker
- Relay Bots: Connect to MULTIPLE brokers (bridge communications)
- C2 Controller: Connects to ALL brokers (full network oversight)
```

## 🚀 Features

- **Multi-Broker Architecture**: Distributed C2 infrastructure across multiple MQTT brokers
- **Dual Bot Types**: 
  - **Client Bots**: Connect to single broker for efficiency and stealth
  - **Relay Bots**: Bridge communications across multiple brokers for redundancy
- **Fault Tolerance**: C2 maintains connections to all brokers for complete network oversight
- **Load Distribution**: Traffic distributed across multiple brokers to avoid detection
- **Encrypted Communication**: Custom cipher implementation for secure MQTT communications
- **Dynamic String Generation**: Runtime obfuscation and identifier generation
- **Topic Generation Algorithm Integration**: TGA-based operations and evasion
- **Scalable Deployment**: Easy scaling with `run_bots.sh` script


## 📁 Project Structure

```
mqtt-based-botnet/
├── bot/                      # Bot client implementation
│   ├── bot.py               # Main bot logic and functionality
│   ├── cipher.py            # Encryption/decryption utilities
│   ├── main.py              # Bot entry point
│   ├── mqtt.py              # MQTT client wrapper
│   ├── run_bots.sh          # Script to spawn multiple bot instances
│   ├── seed_harvesting.py   # Seed generation and harvesting
│   ├── string_generator.py  # Dynamic string generation utilities
│   └── tga_generator.py     # TGA (Truevine Genetic Algorithm) utilities
├── c2/                      # Command & Control server
│   ├── c2.py               # Main C2 controller logic
│   ├── cipher.py           # Encryption/decryption utilities (shared)
│   ├── main.py             # C2 server entry point
│   ├── mqtt.py             # MQTT message handling
│   ├── seed_harvesting.py  # Seed generation and harvesting (shared)
│   ├── string_generator.py # Dynamic string generation (shared)
│   └── tga_generator.py    # TGA utilities (shared)
├── requirements.txt        # Python dependencies
├── .gitignore
├── LICENSE
└── README.md
```


## 🔧 Core Components

### Bot Architecture (`bot/`)
- **`main.py`**: Entry point that initializes and starts the bot client
- **`bot.py`**: Core bot functionality, command processing, and system operations
- **`mqtt.py`**: MQTT client implementation for communication
- **`cipher.py`**: Encryption/decryption module for secure communications
- **`seed_harvesting.py`**: Cryptographic seed generation and management
- **`string_generator.py`**: Dynamic string generation for obfuscation and identification
- **`tga_generator.py`**: Topic Generation Algorithm
- **`run_bots.sh`**: Shell script for launching multiple bot instances simultaneously

### C2 Server Architecture (`c2/`)
- **`main.py`**: C2 server entry point and initialization
- **`c2.py`**: Command and control logic, bot management, and command dispatch
- **`mqtt.py`**: MQTT broker communication and message routing
- **`cipher.py`**: Encryption utilities (shared with bots for compatibility)
- **`seed_harvesting.py`**: Seed generation (shared implementation)
- **`string_generator.py`**: String generation utilities (shared implementation)
- **`tga_generator.py`**: Topic Generation algorithm utilities (shared implementation)

TODO: config and requirements
## 🚀 Quick Start

1. **Clone and Setup**
   ```bash
   git clone https://github.com/winnerozekhome/mqtt-based-botnet.git
   cd mqtt-based-botnet
   pip install -r requirements.txt
   ```

2. **Launch C2 Server**
   ```bash
   cd c2
   python3 main.py
   ```

3. **Deploy Bots**
   ```bash
   cd bot
   # Single bot
   python3 main.py
   
   # Multiple bots (e.g., 5 instances)
   ./run_bots.sh 5
   ```
