# Elastic-Lab19-Detection-Engineering
## Overview
Detection engineering is the process of creating, testing, and improving security detections that identify suspicious or malicious activity from available security telemetry. In a SOC, detections help analysts move from manually searching through large volumes of logs to using repeatable logic that can identify specific attacker behaviors.

The process starts with identifying a behavior such as Windows Event Log clearing, PowerShell execution, scheduled task creation, or service creation. The analyst then determines which Windows events or endpoint fields should represent that behavior and verifies that the required telemetry is actually reaching Elastic.

The main stages are:

- Identify the behavior — Determine what activity needs to be detected.
- Validate telemetry — Confirm the required event IDs, process data, or fields are available.
- Create detection logic — Build an ES|QL query focused on the behavior.
- Test the detection — Compare the detection against controlled activity or existing evidence.
- Tune the detection — Improve the logic and reduce unnecessary results.
- Document limitations — Record missing telemetry or conditions that prevent full validation.

The key principle is that creating a detection query does not automatically mean the detection works. The required telemetry must be available and the detection must be tested against observable evidence before it can be considered validated.


This lab focuses on the practical process of developing and validating security detections using Elastic Security and Windows endpoint telemetry.

The investigation uses behaviors from previous Elastic labs, including Windows Security Event Log clearing, PowerShell execution, scheduled task creation, and Windows service activity. The objective is not only to create detection queries, but also to verify whether the required telemetry is actually available in Elastic.

The lab follows an evidence-driven approach:

**Identify Behavior → Validate Telemetry → Create Detection Logic → Test Detection → Review Results → Document Limitations**

A key finding from this lab was that Windows Security telemetry was available in Elastic, demonstrated by multiple Event ID `4624` records. However, the previously generated Event ID `1102` was confirmed locally on Windows but was not available in the current Elastic search results. Therefore, the `1102` detection could not be fully validated from the existing telemetry.

---

## Lab Objectives

- Understand the practical role of detection engineering in a SOC environment.
- Identify Windows security behaviors that can be converted into SIEM detections.
- Verify that the required endpoint telemetry is available in Elastic before creating detection logic.
- Investigate Windows Security Event ID `1102` and its relevance to defense evasion.
- Develop an ES|QL detection for Windows Security log clearing.
- Compare locally confirmed Windows activity with telemetry available in Elastic.
- Identify and assess PowerShell process telemetry for detection development.
- Investigate the availability of Scheduled Task telemetry in Elastic.
- Investigate available telemetry related to Windows service activity.
- Distinguish between confirmed activity, activity observed in Elastic, and activity that cannot be validated because of telemetry limitations.
- Evaluate detection results without treating missing telemetry as proof that an activity did not occur.
- Understand how broad searches can produce results that do not necessarily represent the intended security behavior.
- Classify detections as validated, partially validated, telemetry limited, or not validated based on available evidence.
- Document detection coverage and endpoint visibility limitations for future tuning.
  
---

## Lab Scenario

A Windows endpoint is being monitored by Elastic Security as part of an ongoing SOC detection-engineering exercise. Previous investigations on the endpoint demonstrated several behaviors that could be relevant to attacker activity, including PowerShell execution, scheduled task creation, Windows service creation, and Security Event Log clearing.

The objective of this lab is to convert these known behaviors into practical detection logic and determine which activities can actually be identified using the telemetry currently available in Elastic.

The investigation begins by validating the health of the Elastic Agent and reviewing the available datasets and Windows event IDs. Event ID `1102` is selected as the primary detection because a controlled Security log clearing event was previously confirmed on the endpoint.

The investigation then compares the locally confirmed `1102` event with Elastic telemetry. Additional detection coverage is examined for PowerShell, Scheduled Tasks, and Windows services to determine whether the required endpoint data is available.

The investigation focuses on:

- Validating available Windows endpoint telemetry.
- Developing detection logic for observable security behaviors.
- Comparing local Windows evidence with Elastic SIEM evidence.
- Identifying telemetry gaps that affect detection coverage.
- Distinguishing confirmed activity from activity that cannot be validated in Elastic.
- Avoiding assumptions when a detection query returns no results.

The expected outcome is a practical assessment of which Windows behaviors can currently be detected in Elastic and which require additional telemetry, configuration, or future tuning.

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

