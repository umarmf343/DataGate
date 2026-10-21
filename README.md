# DataGate — Internet Control 1.2.0

DataGate is a native Windows desktop application for per-application network access controls, live process traffic monitoring, and a recoverable Focus mode built on Windows Firewall. Administrator approval is required for network policy changes and live traffic capture.

## Upgrade audit — 1.2.0

- The first step is now a prominent administrator banner. Read-only, UAC-pending, canceled, and enabled states are explicit. Individual controls are next to the selected app, and each table row has a quick action. Checked batches remain separate from row selection.
- Enable normalizes executable paths and removes all matching DataGate rules by executable identity, including legacy block names and inbound blocks, then verifies the resulting policy. A simulated legacy-block + real TCP Block/Enable roundtrip is part of `--upgrade-test`.
- Block covers both inbound and outbound for the exact executable. This still does not automatically block separate helpers, services, shared runtimes, another version of the app, or a proxy host.
- Review helpers lists related running descendants and executable candidates in a bounded application folder. All candidates start unchecked; reviewing/selecting does not change rules. Add chosen helpers to the checked list, then apply Allow/Block to the reviewed set. A single-app Enable warns when known related executables remain blocked. Folder/process relationships are evidence, not guaranteed dependency analysis. Shared Windows services need deliberate manual investigation, never wholesale approval of svchost.
- Existing external executable block conflicts are shown, without deleting rules owned by Windows or other products. A saved allow rule is never presented as proof that the target application can access the internet. Port/service/package/user/global rules, security policies, VPNs and DNS may also affect the outcome. Restart the target application's connection after a rule change.
- Operation results survive automatic refresh, partial batches report failures, and successful verified rule changes are recorded locally in `%LOCALAPPDATA%/DataGate/Logs/actions.log`. The inventory automatically refreshes approximately every 16 seconds.
- Fixed ETW startup: privately named system-logger sessions require a new GUID, not the reserved SystemTraceControlGuid. Live TCP/UDP attribution is validated with a real local transfer. Closing/disposing the dashboard stops its owned capture session.
- Installation is versioned as `versions/1.2.0`. It preserves all existing restrictions, recovery journals and old executable versions. The installer does not enable Focus or reset any firewall policy.

Administrator-approved verification: `DataGate.exe --upgrade-test` runs read-only/UI regression tests, a temporary policy + TCP connectivity roundtrip for the test executable only, and local TCP/UDP capture. Reports are saved beside the test executable. It does not activate global Focus or modify another app's rules.

References for the audit:
- https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules
- https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session

## Checkbox selection and live usage

Tick the SELECT checkboxes for any number of apps, then choose **Allow checked** or **Block checked**. **Check visible** selects only the rows matching the current search; **Clear checks** clears the entire selection. Checked paths survive filtering and refresh, and the batch confirmation explicitly includes hidden checked apps. A partially failed batch reports the successes and failures rather than pretending that every change succeeded.

After administrator approval, a native Windows ETW system-logger session measures per-executable TCP/UDP IPv4/IPv6 bytes. The dashboard updates download/upload rates in KiB/s and session totals in MiB every two seconds. Multiple processes sharing the same executable are combined. Unknown/protected/very short-lived processes can be unattributed, and their combined bytes are labelled separately. These are observed network bytes including LAN/loopback, not a mobile-network bill, internet-only accounting, historical usage, or an always-on counter. VPNs, shared service hosts, event loss, and process churn can affect attribution. A dash means monitoring is unavailable; it does not mean zero consumption.

Only DataGate's own uniquely named trace session is started/stopped; it does not take over other Windows tracing sessions or record packet contents. Normal closing disposes capture. A forced process termination can leave an orphan ETW session until reboot. Elevation is required to start capture. The application remains native C# with no additional runtime packages or Node modules; the build now targets x64 for correct native ETW layouts. Installation is versioned under `%LOCALAPPDATA%/Programs/DataGate/versions/1.1.0` and preserves older executables and firewall recovery state.

`--monitor-test` requires elevation and validates native ETW startup, real local TCP/UDP bytes attributed to the test executable, and session disposal. It writes `monitor-test.txt` beside the test executable, without changing any firewall rules.

Native Windows Forms / C# application for Windows 10/11 with the included .NET Framework 4.8. No Node.js, Python, cloud account, telemetry, or ongoing app service is required. Compile using `build.ps1` (the Windows Framework compiler is used; no NuGet downloads).

## Installation and use

Run `release/DataGate-Setup.exe` for the per-user installer. The same app can run portably as `DataGate.exe`. Installation creates DataGate and Restore Internet shortcuts on the desktop and Start menu, without changing networking. The `--install` switch performs this same installation without a dialog.

1. Open DataGate and select **Enable controls (Admin)**. Accept Windows' UAC prompt. Non-admin mode is read-only.
2. Refresh running processes; search by name, path, or DataGate status. Add any other local executable with **Add .exe**. Protected processes may only be discoverable when elevated.
3. **Block selected** creates a persistent outbound block for that exact executable. This also blocks its LAN access. **Allow selected** removes DataGate's block and adds an allow rule; it cannot override someone else's explicit block. Closing a window is NOT equivalent to blocking its background helpers.
4. For strongest savings, approve only the executables you need, then start **Focus mode** and read the confirmation. Approvals are persistent, not tied to whether an application window is in the foreground. Newly installed / moved executable paths need new approval.
5. **Stop Focus / recover** restores the earlier default outbound policies and re-enables the outbound allow rules it disabled. Individual DataGate allow/block rules remain. **Restore all DataGate changes** also removes DataGate's own rules. No foreign firewall rules are deleted.

Focus temporarily disables existing outbound allow rules, defaults all three profiles to outbound-block, and adds service-scoped DNS (UDP/TCP 53) and DHCP (UDP 67/547) exceptions for svchost. It refuses inactive firewall profiles and restricted policies. Recovery fingerprints full rule properties and counts enabled instances, rather than relying on duplicate display names. Shared hosts, VPNs, proxies and helper processes complicate app attribution: do not approve generic runtimes or svchost broadly unless you understand what else uses them. Existing connections may need restarting to validate enforcement. No claim of per-app billing-grade traffic accounting is made; the speed card is an aggregate network-adapter estimate (LAN traffic and VPN duplication are possible).

## Recovery and safety

Before changing any profile or existing allow rule, Focus atomically saves a recovery journal to `%ProgramData%/DataGate/firewall-recovery.xml`. Never delete this file while Focus/recovery is active. Recovery errors leave the journal in place so you can retry. The recovery shortcut runs `DataGate.exe --restore`, requests UAC if necessary, restores the journal and removes DataGate's own rules. Close prompts let you restore, keep Focus, or cancel. No Windows service is stopped or disabled. Windows updates and cloud backups may stop during Focus; allow regular maintenance sessions.

Local administrators or centrally managed security software can change/reapply policy. DataGate is an internet-usage control, not tamper-proof protection or a replacement firewall driver. Test your approved applications after enabling Focus. If Windows networking needs additional service exceptions on your configuration, stop Focus rather than approving all of svchost. Don't enable Focus on a remotely accessed machine without someone available locally.

Before manually removing the installation, restore all DataGate changes first. The per-user installer is not MSI and does not register an Apps & Features uninstaller. Remove its installation folder and shortcuts only after recovery. Existing source projects are not modified.

## Validation

`DataGate.exe --self-test` checks deterministic rule IDs, invalid paths, XML recovery roundtrip, actual read-only firewall inventory/fingerprints, and dashboard construction. It writes `test-results.txt` beside the test executable. `--preview` renders a dashboard image without firewall changes. `--verify-firewall` requires elevation and creates/verifies/removes one temporary outbound block for DataGate itself. It also attempts fresh TCP connections to www.microsoft.com:443 before, during and after the block, reporting PASS only for the complete expected sequence. It never changes profiles or blocks another application. Global Focus transitions require a separate, user-confirmed test because they disconnect non-approved applications.

Microsoft references:
- https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules
- https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2

Windows' explicit block rules take precedence over ordinary allow rules. Focus therefore uses a default outbound block, not a blanket explicit block that would prevent selected-app exceptions.
