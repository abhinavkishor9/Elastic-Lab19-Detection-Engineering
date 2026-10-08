# Timeline 

| Time | Activity | Evidence | Assessment |
|---|---|---|---|
| Previous Lab | Controlled Security log clearing performed | Windows Event ID 1102 | Activity generated |
| 07 Oct 2026 05:42:36 | Security audit log cleared | Local Windows Security log | Confirmed |
| 08 Oct 2026 | Elastic Agent status checked | Fleet Healthy / Connected | Agent operational |
| 08 Oct 2026 | Elastic Agent status checked | Agent Healthy / Running | Agent operational |
| 08 Oct 2026 | Dataset inventory performed | `windows.sysmon_operational`, `system.security`, etc. | Telemetry available |
| 08 Oct 2026 | Event ID inventory performed | Multiple Windows/Sysmon event IDs | Event telemetry available |
| 08 Oct 2026 | Event ID 4624 queried | Multiple successful logon events | Security telemetry confirmed |
| 08 Oct 2026 | Event ID 1102 queried | 0 documents | Historical event not observed in Elastic |
| 08 Oct 2026 | Local Event ID 1102 checked | Event present locally | Local activity confirmed |
| 08 Oct 2026 | PowerShell telemetry queried | 341 documents | Process telemetry available |
| 08 Oct 2026 | Task Scheduler telemetry queried | 0 documents | Telemetry not available through tested query |
| 08 Oct 2026 | Service keyword search performed | 271 documents processed | Results primarily Sysmon process events |
| 08 Oct 2026 | Service creation detection assessed | No confirmed service-creation event | Not validated |

---

