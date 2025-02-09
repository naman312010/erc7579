import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

const proxyModule = buildModule("ProxyModule", (m) => {
  const proxyAdminOwner = m.getAccount(0);

  const SA = m.contract("ModularSmartAccount");

  const proxy = m.contract("TransparentUpgradeableProxy", [
    SA,
    proxyAdminOwner,
    "0x",
  ]);

  const proxyAdminAddress = m.readEventArgument(
    proxy,
    "AdminChanged",
    "newAdmin"
  );

  const proxyAdmin = m.contractAt("ProxyAdmin", proxyAdminAddress);

  return { proxyAdmin, proxy };
});

const SAModule = buildModule("SAModule", (m) => {
  const { proxy, proxyAdmin } = m.useModule(proxyModule);

  const SA = m.contractAt("ModularSmartAccount", proxy);

  return { SA, proxy, proxyAdmin };
});

export default SAModule;