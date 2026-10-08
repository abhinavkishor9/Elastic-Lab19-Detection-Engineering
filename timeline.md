# Timeline — Elastic Lab 19

## Detection Engineering Timeline

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

## Key Timeline Events

### 07 Oct 2026 — 05:42:36

A controlled Security log clearing activity from the previous lab generated:

```text
Event ID: 1102
Provider: Microsoft-Windows-Eventlog
Message: The audit log was cleared.
```

This event was confirmed locally.

---

### 08 Oct 2026 — Elastic Agent Validation

Elastic Agent status was checked:

```text
fleet
└─ status: (HEALTHY) Connected

elastic-agent
└─ status: (HEALTHY) Running
```

The endpoint was therefore considered operational for the detection-engineering investigation.

---

### 08 Oct 2026 — Telemetry Inventory

Available datasets were reviewed.

The largest dataset was:

```text
windows.sysmon_operational — 493 documents
```

Other available datasets included:

```text
elastic_agent — 20
system.system — 13
system.security — 8
elastic_agent.metricbeat — 5
```

---

### 08 Oct 2026 — Security Telemetry Validation

Event ID `4624` records were observed in Elastic.

Examples included events associated with:

- SYSTEM
- LOCAL SERVICE
- Dell

This confirmed that Windows Security telemetry was reaching Elastic.

---

### 08 Oct 2026 — Event ID 1102 Detection Test

The Elastic query for Event ID `1102` returned:

```text
0 documents processed
```

However, the same event was confirmed locally in the Windows Security log.

**Assessment:** Local activity confirmed, Elastic event not observed.

---

### 08 Oct 2026 — PowerShell Detection Test

PowerShell process telemetry was successfully returned.

The query processed:

```text
341 documents
```

Examples included:

```text
powershell.exe
powershell.exe -NoProfile -ExecutionPolicy ...
```

**Assessment:** PowerShell process telemetry available.

---

### 08 Oct 2026 — Scheduled Task Detection Test

The Task Scheduler provider query returned:

```text
0 documents processed
```

**Assessment:** Scheduled Task telemetry not available through the tested query.

---

### 08 Oct 2026 — Windows Service Detection Test

The broad service search processed:

```text
271 documents
```

The returned events were primarily Sysmon Process Create events.

**Assessment:** Service creation was not established from the available results.

---

## Final Detection Status

| Detection | Final Status |
|---|---|
| Event ID 1102 | Telemetry Limited |
| PowerShell Process Activity | Validated for Process Telemetry |
| Scheduled Task Activity | Telemetry Limited |
| Windows Service Creation | Not Validated |

## Final Assessment

The investigation established that Elastic endpoint telemetry was operational and that useful PowerShell and Windows Security telemetry was available. However, not every previously observed Windows behavior was represented in the available Elastic data. The final timeline therefore distinguishes confirmed local activity from activity actually observable in Elastic.
