import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import proxyModule from "./ProxyModule";


const upgradeModule = buildModule("UpgradeModule", (m) => {
    const proxyAdminOwner = m.getAccount(0);
  
    const { proxyAdmin, proxy } = m.useModule(proxyModule);
  
    const SAV2 = m.contract("ModularSmartAccountV2");
  
    const encodedFunctionCall = m.encodeFunctionCall(SAV2, "setName", [
      "Example Name",
    ]);
  
    m.call(proxyAdmin, "upgradeAndCall", [proxy, SAV2, encodedFunctionCall], {
      from: proxyAdminOwner,
    });
  
    return { proxyAdmin, proxy };
  });

  const SAV2Module = buildModule("SAV2Module", (m) => {
    const { proxy } = m.useModule(upgradeModule);
  
    const SAV2 = m.contractAt("DemoV2", proxy);
  
    return { SAV2 };
  });

  export default SAV2Module;