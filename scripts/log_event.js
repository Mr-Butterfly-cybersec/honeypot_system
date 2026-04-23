const fs = require("fs");
const path = require("path");
const { ethers } = require("ethers");

const root = path.resolve(__dirname, "..");
const deploymentPath = path.join(root, "blockchain", "deployment.json");

function bytes32FromText(value) {
  if (/^0x[0-9a-fA-F]{64}$/.test(value)) {
    return value;
  }
  return ethers.keccak256(ethers.toUtf8Bytes(value));
}

function bytes32FromHex(value) {
  if (/^[0-9a-fA-F]{64}$/.test(value)) {
    return `0x${value}`;
  }
  return bytes32FromText(value);
}

async function main() {
  if (!process.argv[2]) {
    throw new Error("Usage: node scripts/log_event.js '<json-payload>'");
  }
  if (!fs.existsSync(deploymentPath)) {
    throw new Error("Missing blockchain/deployment.json. Run npm run blockchain:deploy first.");
  }

  const event = JSON.parse(process.argv[2]);
  const deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf8"));
  const provider = new ethers.JsonRpcProvider(process.env.RPC_URL || deployment.rpcUrl);
  const signer = await provider.getSigner(0);
  const contract = new ethers.Contract(deployment.address, deployment.abi, signer);

  const tx = await contract.logEvent(
    bytes32FromText(event.eventId),
    bytes32FromHex(event.eventHash),
    bytes32FromHex(event.previousHash),
    bytes32FromHex(event.ipHash),
    Number(event.severity)
  );
  const receipt = await tx.wait();

  console.log(
    JSON.stringify({
      transactionHash: receipt.hash,
      blockNumber: receipt.blockNumber,
      contractAddress: deployment.address,
    })
  );
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
