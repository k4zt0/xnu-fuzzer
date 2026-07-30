# Apple built-in driver (IOKit) targets

`xfuzz` discovers IOKit user-client targets dynamically at startup
(`xf_iokit_discover`): it walks the IORegistry, tries `IOServiceOpen` on each
service node across several user-client type selectors, and turns every node
that actually opens into a fuzzing target. Each target is driven via
`IOConnectCallMethod` (→ `IOUserClient::externalMethod` in the kernel) with a
fuzzed selector plus scalar and struct-input payloads.

## Access model

- **Non-root**: almost all Apple user clients refuse `IOServiceOpen` (they
  require root and/or code-signing entitlements). In practice only a handful
  open — e.g. `RootDomainUserClient`. Power-management clients
  (`RootDomainUserClient`, `IOPMrootDomain`) are on the **safe-mode denylist**
  because a fuzzed method can sleep or shut the machine down.
- **Root (LaunchDaemon)**: most non-entitlement-gated Apple drivers become
  openable. This is the intended deployment for real Apple-driver fuzzing.
- **Always denied** (entitlement/secure-boot gated, and on the denylist):
  `AppleSEPUserClient`, `AppleKeyStoreUserClient`, `AppleFDEKeyStoreUserClient`,
  `AppleMobileFileIntegrityUserClient`, `BootPolicyUserClient`,
  `AppleImage4UserClient`, `AppleFirmwareUpdateUserClient`, …

## Apple IOUserClient classes present on this hardware (Mac17,5, macOS 26.4.1)

Enumerated from `ioreg` — 97 classes. High-value, historically bug-prone
targets (open under root) include:

- **Graphics / display**: `AppleDCPLinkService`, `DCPAV*ProxyUserClient`,
  `DCPDP*ProxyUserClient`, `IODPPortUserClient`
- **HID**: `IOHIDLibUserClient`, `IOHIDResourceDeviceUserClient`,
  `IOHIDEventServiceUserClient`, `AppleMultitouchDeviceUserClient`,
  `AppleHIDTransport*UserClient`
- **Crypto / accel**: `IOAESAcceleratorUserClient`, `AppleSSEUserClient`,
  `AppleMesaUserClient`
- **Storage / FS**: `AppleAPFSUserClient`, `IOUSBMassStorageUserClient`,
  `IOHDIXControllerUserClient`, `DIDeviceIOUserClient`
- **Platform / SoC**: `AppleSMCClient`, `ApplePMGRUserClient`,
  `AppleARMIICUserClient`, `AppleARMSPMIControllerUserClient`,
  `IODARTClient`, `IODARTMapperClient`, `AppleCLPCUserClient`
- **Networking**: `IONetworkStackUserClient`, `IOUserEthernetResourceUserClient`
- **Audio**: `IOPAudio*DeviceUserClient`
- **Reporting / analytics**: `IOReportUserClient`, `CoreAnalyticsUserClient`
- **Power**: `RootDomainUserClient` (denylisted in safe mode)

The discovery step probes and records whichever of these actually open in the
current privilege context, so the effective target set adapts to how `xfuzz`
is run.
