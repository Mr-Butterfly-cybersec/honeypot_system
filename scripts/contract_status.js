const fs = require("fs");
const path = require("path");
const { ethers } = require("ethers");

const root = path.resolve(__dirname, "..");
const deploymentPath = path.join(root, "blockchain", "deployment.json");

async function main() {
  if (!fs.existsSync(deploymentPath)) {
    throw new Error("Missing blockchain/deployment.json. Run npm run blockchain:deploy first.");
  }

  const deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf8"));
  const provider = new ethers.JsonRpcProvider(process.env.RPC_URL || deployment.rpcUrl);
  const contract = new ethers.Contract(deployment.address, deployment.abi, provider);
  const count = await contract.getEventCount();

  console.log(
    JSON.stringify(
      {
        contractAddress: deployment.address,
        eventCount: count.toString(),
        rpcUrl: deployment.rpcUrl,
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
