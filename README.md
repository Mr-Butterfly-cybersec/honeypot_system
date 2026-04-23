# Deception Based Security Mechanism

This project implements Task 3 from the Cybersecurity & Network Security Internship Assessment. It uses two deception traps and records every trap interaction as suspicious activity.

## Implemented Scope

- Trap 1: fake administrator login at `/admin`
- Trap 2: dummy internal API at `/api/internal/config`
- Continuous monitoring of trap interactions
- Suspicious/malicious severity scoring
- SQLite event storage
- Local tamper-evident hash chain
- Dashboard for events, severity, and simulated blocking
- Verification page for audit-chain integrity
- Solidity smart contract for blockchain anchoring on local Ganache

## Run the Core App

The Python web app uses the standard library only.

```bash
python3 app.py
```

By default this starts two separated servers:

- Trap server: `http://127.0.0.1:8000`
- Internal dashboard server: `http://127.0.0.1:9000`

Open:

- Trap home: `http://127.0.0.1:8000/`
- Fake admin trap: `http://127.0.0.1:8000/admin`
- Dummy API trap: `http://127.0.0.1:8000/api/internal/config`
- Dashboard: `http://127.0.0.1:9000/dashboard`
- Verification: `http://127.0.0.1:9000/verify`
- Events API: `http://127.0.0.1:9000/api/events`

You can also run one role at a time:

```bash
python3 app.py --mode trap --port 8000
python3 app.py --mode dashboard --port 9000
```

## Run the Blockchain Layer

Install the Node dependencies:

```bash
npm install
```

Start Ganache in one terminal:

```bash
npm run blockchain:ganache
```

Deploy the Solidity contract in another terminal:

```bash
npm run blockchain:deploy
```

After deployment, `blockchain/deployment.json` is created. When the Python app records a new trap event, it automatically calls `scripts/log_event.js` and writes the event proof to the deployed contract.

Check how many events are stored in the contract:

```bash
npm run blockchain:status
```

## Test Everything

Run the full smoke test:

```bash
npm run test:system
```

The test starts or reuses Ganache, deploys the contract, starts the trap server on port `8123` and dashboard server on port `9123`, triggers both traps, checks route separation, checks the local hash-chain verification, and confirms that events were anchored to the contract.

## Demo Flow

1. Start Ganache.
2. Deploy the contract.
3. Start the Python web app.
4. Visit trap server `/admin`.
5. Submit any credentials to the fake login form.
6. Visit trap server `/api/internal/config`.
7. Open dashboard server `/dashboard` and confirm the events, severity, and blockchain status.
8. Open dashboard server `/verify` to confirm the local hash chain has not been modified.
9. Run `npm run blockchain:status` to show the Ganache contract event count.

## Why This Meets Task 3

The assignment asks for a deception based system with at least one misleading component, monitoring, suspicious activity identification, and alerts or responses.

This implementation has two misleading components:

- A fake login page that no legitimate user should access.
- A dummy internal configuration API that no normal workflow uses.

Every interaction with these components creates a security event. Events are scored, displayed in the dashboard, linked by hashes, and optionally anchored to a local blockchain contract.
