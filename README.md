# Deception-Based Honeypot Security System with Blockchain Audit Proof

![Architecture Flowchart](images/clipboard-1776938649421.png)

This project is an advanced, deception-based honeypot system designed to identify, monitor, and permanently log malicious activity. By deploying decoy resources that no legitimate user should ever access, the system safely captures attacker behavior, scores its severity, and anchors cryptographic proof of the event to a local blockchain to guarantee a tamper-evident audit trail.

## Core Architecture

The system is built on a highly segmented architecture:

1.  **Deception Trap Layer (Port 8000):** The public-facing attack surface containing decoy endpoints (e.g., a fake `/admin` login and a dummy `/api/internal/config`).
2.  **Event Capture & Scoring:** The Python backend monitors all interactions. It captures metadata (timestamp, method, hashed IP, User-Agent) and calculates a severity score (Low, Medium, High, Critical) based on attacker behavior. Sensitive payloads (like submitted passwords) are never stored in plaintext; they are securely hashed using HMAC-SHA256.
3.  **Tamper-Evident Local Storage:** Events are stored in a local SQLite database (`data/honeypot.db`). Each event calculates a cryptographic hash that includes the hash of the *previous* event, creating an unbreakable local hash chain.
4.  **Blockchain Audit Proof Layer:** To guarantee log integrity, a compact cryptographic proof of each event (Event Hash, Previous Hash, IP Hash, Severity) is sent to a Solidity smart contract (`HoneypotAuditLog.sol`) deployed on a local Ganache blockchain.
5.  **Dashboard & Verification Layer (Port 9000):** A completely isolated, internal dashboard used by defenders to view live alerts, check the status of simulated IP blocklists, and actively verify the mathematical integrity of the local hash chain against the blockchain ledger.

## Prerequisites

- **Python 3.8+** (Uses standard library only, no `pip` installs required)
- **Node.js & npm** (For the blockchain bridging scripts)
- **Ganache GUI** (or CLI) for the local blockchain network

## Setup & Running the System

### 1. Install Dependencies
Install the required Node.js packages (`ethers`, `solc`) used to communicate with the blockchain:
```bash
npm install
```

### 2. Start the Blockchain Network
You can use the Ganache GUI (recommended, configure to port `8545` and Network ID `1337`) or run the CLI version:
```bash
npm run blockchain:ganache
```

### 3. Deploy the Smart Contract
In a new terminal window, compile and deploy the `HoneypotAuditLog` smart contract to your running Ganache network:
```bash
npm run blockchain:deploy
```

### 4. Start the Honeypot Servers
Run the main Python application. This will simultaneously start the public Trap Server and the isolated internal Dashboard Server:
```bash
python3 app.py
```

## System Usage & Navigation

Once the system is running, you can interact with the different segmented surfaces:

**The Attack Surface (Public)**
- **Trap 1 (Fake Admin):** `http://127.0.0.1:8000/admin` (Try submitting fake credentials)
- **Trap 2 (Dummy API):** `http://127.0.0.1:8000/api/internal/config`

**The Defender Surface (Internal/Restricted)**
- **Monitoring Dashboard:** `http://127.0.0.1:9000/dashboard`
- **Chain Verification Tool:** `http://127.0.0.1:9000/verify` (Recalculates the local hash chain to ensure no database tampering has occurred).
- **JSON Events API:** `http://127.0.0.1:9000/api/events`

## Automated Testing

To verify the entire pipeline—from trap triggering to hash chain generation and blockchain anchoring—run the automated system test:

```bash
npm run test:system
```
This script ensures the deployment is successful, triggers multiple traps, verifies the resulting local database hashes, and confirms the transactions were successfully mined on the Ganache network.
