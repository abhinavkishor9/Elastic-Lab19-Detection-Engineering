# Investigation Notes 

## Initial Agent Validation

The Elastic Agent was checked before starting the detection work.

```powershell
& "C:\Program Files\Elastic\Agent\elastic-agent.exe" status
```

Observed status:

```text
fleet
└─ status: (HEALTHY) Connected

elastic-agent
└─ status: (HEALTHY) Running
```

### Assessment

The agent was healthy and connected to Fleet. No agent re-enrollment was required.

---

## Dataset Inventory

The following query was used to identify available datasets:

```esql
FROM logs-*
| STATS event_count = count() BY data_stream.dataset
| SORT event_count DESC
```

Observed:

| Dataset | Event Count |
|---|---:|
| `windows.sysmon_operational` | 493 |
| `elastic_agent` | 20 |
| `system.system` | 13 |
| `system.security` | 8 |
| `elastic_agent.metricbeat` | 5 |

### Assessment

Elastic was actively receiving endpoint telemetry. Sysmon represented the largest available dataset, while Windows Security telemetry was also present.

---

## Event Code Inventory

The following query was used to identify available event IDs:

```esql
FROM logs-*
| WHERE event.code IS NOT NULL
| STATS event_count = count() BY event.code
| SORT event_count DESC
```

Observed event IDs included:

- Event ID `1`
- Event ID `2`
- Event ID `3`
- Event ID `5`
- Event ID `11`
- Additional event IDs

Event ID `1` was heavily represented and corresponded to Sysmon process creation activity.

---

## Security Event 4624 Validation

Windows Security logon telemetry was confirmed in Elastic.

Observed records included:

```text
Oct 8, 2026 @ 06:36:40.180
desktop-9mmm37v
SYSTEM
4624
An account was successfully logged on.
```

Additional `4624` events were observed for:

- SYSTEM
- LOCAL SERVICE
- Dell

### Assessment

This confirmed that Windows Security telemetry was reaching Elastic and could be queried using `event.code`.

---

## Detection Investigation — Event ID 1102

### Local Evidence

The Windows Security log was queried directly:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 5 |
Select-Object TimeCreated, Id, ProviderName, Message
```

Observed:

```text
07-10-2026 05:42:36
1102
Microsoft-Windows-Eventlog
The audit log was cleared....
```

### Elastic Query

```esql
FROM logs-*
| WHERE event.code == "1102"
| KEEP @timestamp, host.name, user.name, event.code, message
| SORT @timestamp DESC
```

### Elastic Result

```text
0 documents processed
```

### Assessment

The Security log clearing event was confirmed on the Windows endpoint but was not returned by the current Elastic query.

The correct conclusion is therefore:

**Local activity confirmed → Elastic event not observed → Detection telemetry limited**

It would be incorrect to conclude that the Security log clearing did not occur.

---

## PowerShell Detection Investigation

The following query was used:

```esql
FROM logs-*
| WHERE process.name IN ("powershell.exe", "pwsh.exe")
| KEEP @timestamp, host.name, user.name, process.name, process.command_line
```

### Result

The query processed `341` documents.

Observed records included:

```text
powershell.exe
SYSTEM
-
```

and:

```text
powershell.exe
powershell.exe -NoProfile -ExecutionPolicy ...
```

### Assessment

Elastic has process telemetry for PowerShell, including `process.name` and, in some events, `process.command_line`.

This provides a usable telemetry source for future PowerShell detections.

### Status

**Validated for Process Telemetry**

---

## Scheduled Task Investigation

The following query was used:

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

No Task Scheduler provider events were returned.

### Assessment

The absence of matching telemetry means that a reliable scheduled-task detection could not be validated from the current dataset.

### Status

**Telemetry Limited**

---

## Windows Service Investigation

A broad search was performed:

```esql
FROM logs-*
| WHERE message LIKE "*service*"
| KEEP @timestamp, host.name, event.code, event.provider, message
| SORT @timestamp DESC
```

### Result

The query processed `271` documents and returned 20 results.

The returned events were primarily Sysmon process creation events:

```text
event.code: 1
event.provider: Microsoft-Windows-Sysmon
message: Process Create
```

### Assessment

The keyword `service` appearing in a message is not sufficient evidence of Windows service creation.

The available results therefore did not establish that a service-creation event was observed.

### Status

**Not Validated**

---

