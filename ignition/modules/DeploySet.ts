import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

const SetDeploy =  buildModule("SetDeploy", (m) => {
  const EP = m.contract("EntryPoint");
  const validator = m.contract("TimeBasedValidator");
  return { EP, validator };
});

export default SetDeploy;