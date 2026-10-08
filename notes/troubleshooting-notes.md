# Troubleshooting Notes 

## Issue 1 — Event ID 1102 Not Returned by Elastic

### Symptom

The following Elastic query returned no documents:

```esql
FROM logs-*
| WHERE event.code == "1102"
| KEEP @timestamp, host.name, user.name, event.code, message
| SORT @timestamp DESC
```

Result:

```text
0 documents processed
```

### Local Verification

The Windows Security log was checked directly:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 5 |
Select-Object TimeCreated, Id, ProviderName, Message
```

The event was present locally:

```text
07-10-2026 05:42:36
1102
Microsoft-Windows-Eventlog
The audit log was cleared....
```

### Finding

The event existed locally but was not returned by Elastic.

The event was generated during the previous controlled investigation, before Windows Security telemetry was fully available in the current Elastic ingestion state.

### Final Assessment

**Telemetry limitation — not evidence that the event did not occur.**

---

## Issue 2 — Confirming Security Telemetry

### Test

A query for Event ID `4624` was used:

```esql
FROM logs-*
| WHERE event.code == "4624"
| KEEP @timestamp, host.name, user.name, event.code, message
| SORT @timestamp DESC
```

### Result

Multiple `4624` events were returned.

Examples included:

```text
SYSTEM
LOCAL SERVICE
Dell
```

### Finding

Windows Security telemetry is currently reaching Elastic.

This confirms that the absence of the historical `1102` event should not be interpreted as a complete failure of Security telemetry.

---

## Issue 3 — Task Scheduler Query Returned No Results

### Query

```esql
FROM logs-*
| WHERE event.provider LIKE "*TaskScheduler*"
| KEEP @timestamp, host.name, event.code, event.provider, message
| SORT @timestamp DESC
```

### Result

```text
0 documents processed
```

### Finding

No matching Task Scheduler provider events were available through the tested query.

### Final Assessment

The scheduled task behavior cannot currently be validated as an Elastic detection using this telemetry.

**Status: Telemetry Limited**

---

## Issue 4 — Service Search Returned Unexpected Results

### Query

```esql
FROM logs-*
| WHERE message LIKE "*service*"
| KEEP @timestamp, host.name, event.code, event.provider, message
| SORT @timestamp DESC
```

### Result

The query processed `271` documents.

The returned records were primarily:

```text
event.code: 1
event.provider: Microsoft-Windows-Sysmon
message: Process Create
```

### Finding

The search matched the word `service` within event messages, but the results did not prove that Windows service creation occurred.

### Final Assessment

A broad keyword search is insufficient to establish a service-creation detection.

**Status: Not Validated**

---

## Issue 5 — PowerShell Telemetry Available

### Query

```esql
FROM logs-*
| WHERE process.name IN ("powershell.exe", "pwsh.exe")
| KEEP @timestamp, host.name, user.name, process.name, process.command_line
```

### Result

The query processed `341` documents.

PowerShell process activity was visible, including:

```text
powershell.exe
powershell.exe -NoProfile -ExecutionPolicy ...
```

### Finding

Elastic currently has useful PowerShell process telemetry.

### Final Assessment

PowerShell process telemetry is available for detection engineering.

**Status: Validated for Process Telemetry**

---

## Issue 6 — Dataset Validation

### Query

```esql
FROM logs-*
| STATS event_count = count() BY data_stream.dataset
| SORT event_count DESC
```

### Result

```text
windows.sysmon_operational    493
elastic_agent                  20
system.system                  13
system.security                 8
elastic_agent.metricbeat        5
```

### Finding

Multiple datasets were actively receiving data.

The Elastic Agent itself was also confirmed healthy:

```powershell
& "C:\Program Files\Elastic\Agent\elastic-agent.exe" status
```

Result:

```text
fleet
└─ status: (HEALTHY) Connected

elastic-agent
└─ status: (HEALTHY) Running
```

### Final Assessment

The agent and Elastic ingestion pipeline were operational during the investigation.

---

