const fs = require("fs");
const path = require("path");
const solc = require("solc");
const { ethers } = require("ethers");

const root = path.resolve(__dirname, "..");
const contractPath = path.join(root, "contracts", "HoneypotAuditLog.sol");
const outputPath = path.join(root, "blockchain", "deployment.json");
const rpcUrl = process.env.RPC_URL || "http://127.0.0.1:8545";

function compile() {
  const source = fs.readFileSync(contractPath, "utf8");
  const input = {
    language: "Solidity",
    sources: {
      "HoneypotAuditLog.sol": { content: source },
    },
    settings: {
      evmVersion: "paris",
      outputSelection: {
        "*": {
          "*": ["abi", "evm.bytecode"],
        },
      },
    },
  };

  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = output.errors || [];
  const fatal = errors.filter((item) => item.severity === "error");
  if (fatal.length > 0) {
    throw new Error(fatal.map((item) => item.formattedMessage).join("\n"));
  }

  return output.contracts["HoneypotAuditLog.sol"].HoneypotAuditLog;
}

async function main() {
  const compiled = compile();
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const signer = await provider.getSigner(0);
  const factory = new ethers.ContractFactory(compiled.abi, compiled.evm.bytecode.object, signer);
  const contract = await factory.deploy();
  await contract.waitForDeployment();

  const deployment = {
    contractName: "HoneypotAuditLog",
    address: await contract.getAddress(),
    rpcUrl,
    abi: compiled.abi,
    deployedAt: new Date().toISOString(),
  };

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, JSON.stringify(deployment, null, 2));
  console.log(JSON.stringify(deployment, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
