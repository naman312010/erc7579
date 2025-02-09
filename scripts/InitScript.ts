import hre from "hardhat";
import SetDeploy from "../ignition/modules/DeploySet";
import SAModule from "../ignition/modules/ProxyModule";

async function main() {
    console.log("Deploying EntryPoint and Validator...");
    const { EP, validator } = await hre.ignition.deploy(SetDeploy, {});

    console.log("Deploying Modular Smart Account and Proxy...");
    const { proxy } = await hre.ignition.deploy(SAModule, {});

    // Get the deployed proxy address
    const proxyAddress = await proxy.getAddress();

    // Get the Modular Smart Account contract at the proxy address (interact with it as an implementation)
    const SAProxy = await hre.ethers.getContractAt("ModularSmartAccount", proxyAddress);

    console.log("Initializing the Smart Account...");
    const tx = await SAProxy.initializeAccount(await EP.getAddress(), "0x");
    await tx.wait();

    console.log(`Deployment successful!`);
    console.log(`SA Proxy deployed at: ${proxyAddress}`);
    console.log(`EntryPoint deployed at: ${await EP.getAddress()}`);
    console.log(`Validator deployed at: ${await validator.getAddress()}`);
}

main().catch(console.error);
