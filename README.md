# Elastic Lab 19 — Detection Engineering

## Overview

This lab focuses on the practical process of developing and validating security detections using Elastic Security and Windows endpoint telemetry.

The investigation uses behaviors from previous Elastic labs, including Windows Security Event Log clearing, PowerShell execution, scheduled task creation, and Windows service activity. The objective is not only to create detection queries, but also to verify whether the required telemetry is actually available in Elastic.

The lab follows an evidence-driven approach:

**Identify Behavior → Validate Telemetry → Create Detection Logic → Test Detection → Review Results → Document Limitations**

A key finding from this lab was that Windows Security telemetry was available in Elastic, demonstrated by multiple Event ID `4624` records. However, the previously generated Event ID `1102` was confirmed locally on Windows but was not available in the current Elastic search results. Therefore, the `1102` detection could not be fully validated from the existing telemetry.

---

## Objectives

- Understand the basic detection engineering workflow.
- Verify the health of the Elastic Agent before testing detections.
- Identify which Windows telemetry is currently available in Elastic.
- Review available Windows event IDs.
- Develop an Event ID `1102` detection.
- Validate local Windows evidence against Elastic telemetry.
- Review PowerShell process telemetry.
- Investigate telemetry availability for scheduled task activity.
- Investigate telemetry availability for Windows service activity.
- Distinguish between confirmed activity and missing telemetry.
- Document detection limitations and validation status.

---

## Environment

| Component | Details |
|---|---|
| Operating System | Windows 11 Pro |
| Host | `DESKTOP-9MMM37V` |
| Elastic Agent | 9.5.4 |
| Elastic Agent Status | Healthy / Running |
| Fleet Status | Healthy / Connected |
| Elastic Platform | Elastic Cloud |
| Primary Dataset | `windows.sysmon_operational` |
| Security Dataset | `system.security` |
| SIEM Query Language | ES|QL |

---

## Detection Engineering Approach

Detection engineering starts with a specific security behavior and determines whether that behavior can be reliably identified using available telemetry.

The main stages used in this lab are:

1. Identify the behavior.
2. Determine the expected telemetry.
3. Verify that the telemetry is available.
4. Create detection logic.
5. Test the detection against available evidence.
6. Review the results.
7. Identify false-positive or visibility considerations.
8. Document the final detection status.

A detection query is not considered validated simply because the query is syntactically correct. The underlying telemetry must also be available and observable during testing.

---

## Detection 1 — Windows Security Log Clearing

### Behavior

Windows Event ID `1102` is generated when the Windows Security audit log is cleared.

**MITRE ATT&CK:** T1070.001 — Clear Windows Event Logs

### Local Validation

The event was confirmed locally using Windows Event Viewer telemetry:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 5 |
Select-Object TimeCreated, Id, ProviderName, Message
```

Observed:

```text
TimeCreated            Id ProviderName               Message
-----------            -- ------------               -------
07-10-2026 05:42:36    1102 Microsoft-Windows-Eventlog The audit log was cleared....
```

### Elastic Detection

```esql
FROM logs-*
| WHERE event.code == "1102"
| KEEP @timestamp, host.name, user.name, event.code, message
| SORT @timestamp DESC
```

### Result

The query returned:

```text
0 documents processed
```

The event was therefore **confirmed locally but not observed in Elastic**.

### Detection Status

**Telemetry Limited / Not Validated**

The absence of the event in Elastic does not indicate that the activity did not occur. The local Windows Security log confirms that Event ID `1102` was generated.

---

## Detection 2 — PowerShell Activity

PowerShell telemetry was available in Elastic.

### Detection Query

```esql
FROM logs-*
| WHERE process.name IN ("powershell.exe", "pwsh.exe")
| KEEP @timestamp, host.name, user.name, process.name, process.command_line
```

### Result

The query processed `341` documents and returned PowerShell process activity.

Examples included:

- `powershell.exe`
- `SYSTEM`
- `powershell.exe -NoProfile -ExecutionPolicy ...`

### Detection Status

**Validated for Process Telemetry**

The presence of PowerShell process and command-line fields confirms that Elastic has usable process telemetry for PowerShell detection.

This does not automatically mean every suspicious PowerShell technique will be detected; detection logic still needs to be developed and tested against specific behaviors.

---

## Detection 3 — Scheduled Task Activity

Scheduled task activity was investigated using Task Scheduler provider information.

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

No Task Scheduler provider events were returned.

### Detection Status

**Telemetry Limited**

The previous controlled lab activity demonstrated scheduled task creation locally, but the required Task Scheduler telemetry was not available through this query in Elastic.

---

## Detection 4 — Windows Service Activity

Windows service-related activity was investigated using a broad message search.

### Query

```esql
FROM logs-*
| WHERE message LIKE "*service*"
| KEEP @timestamp, host.name, event.code, event.provider, message
| SORT @timestamp DESC
```

### Result

The query processed `271` documents and returned results.

However, the returned records were primarily:

```text
event.code: 1
event.provider: Microsoft-Windows-Sysmon
message: Process Create
```

The presence of the word `service` in the message search did not establish that a Windows service was created.

### Detection Status

**Not Validated**

The query demonstrated that matching telemetry exists, but it did not provide sufficient evidence to confirm Windows service creation.

This illustrates why broad keyword searches should not automatically be treated as reliable detections.

---

## Telemetry Validation

The Elastic Agent was healthy during the investigation.

```text
fleet
└─ status: (HEALTHY) Connected

elastic-agent
└─ status: (HEALTHY) Running
```

Dataset inventory showed:

| Dataset | Documents |
|---|---:|
| `windows.sysmon_operational` | 493 |
| `elastic_agent` | 20 |
| `system.system` | 13 |
| `system.security` | 8 |
| `elastic_agent.metricbeat` | 5 |

Windows event-code inventory also confirmed multiple event IDs were available.

---

## Key Findings

### Confirmed Locally

- Windows Event ID `1102` was generated during the controlled investigation.
- The Security log clearing occurred at `07-10-2026 05:42:36`.
- PowerShell activity was present on the endpoint.
- Elastic Agent was healthy and connected.

### Observed in Elastic

- PowerShell process telemetry was available.
- Windows Security Event ID `4624` telemetry was available.
- Sysmon process creation telemetry was available.
- `system.security` data was present in the dataset inventory.

### Not Observed in Elastic

- The historical Event ID `1102` event was not returned by the Elastic query.
- Task Scheduler provider events were not returned.

### Not Established

- The broad service keyword search did not establish Windows service creation.

---

## Evidence Classification

| Activity | Local Evidence | Elastic Evidence | Status |
|---|---|---|---|
| Security Log Clearing | Confirmed | Not observed | Telemetry Limited |
| PowerShell | Confirmed | Observed | Validated for process telemetry |
| Scheduled Task | Previously confirmed | Not observed | Telemetry Limited |
| Windows Service | Previously controlled | Not established | Not Validated |
| Security Logon 4624 | Confirmed | Observed | Telemetry Available |

---

## Conclusion

This lab demonstrated that detection engineering requires more than writing a query. The analyst must first establish whether the required telemetry exists, test the detection against observable evidence, and distinguish between a failed detection and a telemetry limitation. Event ID `1102` was confirmed locally but was not available in the current Elastic results, while PowerShell and Windows Security `4624` telemetry were successfully observed. The results provide a practical example of building detections based on actual visibility rather than assumptions.

---

