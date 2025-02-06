import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import proxyModule from "./ProxyModule";


const demoModule = buildModule("DemoModule", (m) => {
    const { proxy, proxyAdmin } = m.useModule(proxyModule);
  
    const demo = m.contractAt("Demo", proxy);
  
    return { demo, proxy, proxyAdmin };
  });

  export default demoModule;