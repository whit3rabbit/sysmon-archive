# Sysmon v4.90 XML Configuration File Guide

This document is your comprehensive guide to creating valid Sysmon configuration files in XML format for version 4.90. It is structured according to the underlying schema definition and provides detailed information and examples for each configurable element, attribute, and condition to help you tailor Sysmon to your specific monitoring needs.

**Schema Version:** 4.90

## 1.  Understanding Sysmon XML Configuration

Sysmon is configured using an XML file that defines global settings and event filtering rules. This guide will walk you through the structure of this XML, enabling you to create configurations that precisely define what Sysmon monitors and logs.

**Key XML Configuration Components:**

*   **Global Configuration Entries:** XML elements directly under the `<Sysmon>` root that set Sysmon's general operating parameters.
*   **Event Filtering (`<EventFiltering>`):** The XML section containing all event filtering rules.
*   **Event Filtering Entries:** XML elements within `<EventFiltering>` (e.g., `<ProcessCreate>`, `<NetworkConnect>`) that target specific Sysmon event types for filtering.
*   **Rules (`<Rule>`):** XML elements used to group conditions and define filtering logic.
*   **Rule Groups (`<RuleGroup>`):** XML elements to organize rules into logical groups with "AND" or "OR" relationships.
*   **Conditions:** Attributes and XML elements that specify the criteria for matching event properties.

## 2. Sysmon Event IDs and XML Filtering Entries

The table below maps Sysmon Event IDs to their corresponding XML Event Filtering Entry tag names used in your configuration file.

| Event ID | XML Filtering Entry         | Description                                               |
| :------- | :---------------------------- | :-------------------------------------------------------- |
| 1        | `<ProcessCreate>`             | Process creation events                                  |
| 2        | `<FileCreateTime>`            | File creation time changed events                         |
| 3        | `<NetworkConnect>`            | Network connection events                                 |
| 5        | `<ProcessTerminate>`          | Process termination events                                |
| 6        | `<DriverLoad>`                | Driver load events                                       |
| 7        | `<ImageLoad>`                 | Image load events                                        |
| 8        | `<CreateRemoteThread>`        | Create remote thread events                              |
| 9        | `<RawAccessRead>`             | Raw access read events                                   |
| 10       | `<ProcessAccess>`             | Process access events                                    |
| 11       | `<FileCreate>`                | File create events                                       |
| 12, 13, 14| `<RegistryEvent>` (up to 3)   | Registry object create/delete/value set/rename events    |
| 15       | `<FileCreateStreamHash>`      | File create stream hash events                            |
| 17, 18| `<PipeEvent>` (up to 2)         | Pipe created/connected events                             |
| 19       | `<WmiEventFilter>`            | WMI event filter activity events                          |
| 20       | `<WmiEventConsumer>`          | WMI event consumer activity events                        |
| 21       | `<WmiEventBinding>`           | WMI event consumer to filter binding events             |
| 22       | `<DnsQuery>`                  | DNS query events                                         |
| 23       | `<FileDelete>`                | File delete archived events                               |
| 24       | `<ClipboardChange>`           | Clipboard change events                                  |
| 25       | `<ProcessTampering>`          | Process tampering events                                 |
| 26       | `<FileDeleteDetected>`        | File delete detected events                               |
| 27       | `<FileBlockExecutable>`       | File block executable events                              |
| 28       | `<FileBlockShredding>`        | File block shredding events                               |
| 29       | `<FileExecutableDetected>`    | File executable detected events                           |

**Important:**

*   You can include up to three `<RegistryEvent>` XML elements and up to two `<PipeEvent>` elements in your configuration file to potentially filter different subtypes within these event categories.

## 3. Global Configuration Entries (XML Elements under `<Sysmon>`)

These XML elements, placed directly under the `<Sysmon>` root element, configure global Sysmon settings. All are optional.

| Configuration Entry          | XML Tag                 | Type       | Description                                                                  | XML Example                                      |
| :--------------------------- | :---------------------- | :--------- | :--------------------------------------------------------------------------- | :----------------------------------------------- |
| **Archive Directory**        | `<ArchiveDirectory>`    | `xs:string` | Directory to archive deleted files (FileDelete event). Default: "Sysmon" in volume roots. | `<ArchiveDirectory>D:\SysmonArchives</ArchiveDirectory>` |
| **Capture Clipboard**        | `<CaptureClipboard>`    | Empty Tag  | Enables clipboard capture (ClipboardChange event). Presence enables.          | `<CaptureClipboard/>`                             |
| **Driver Name**              | `<DriverName>`          | `xs:string` | Custom name for Sysmon driver and service images. Advanced option.           | `<DriverName>MySysmonDriver</DriverName>`         |
| **Pipe Monitoring Config**   | `<PipeMonitoringConfig>`| `xs:string` | Pipe monitoring configuration string. Format not defined in schema.         | `<PipeMonitoringConfig>AdvancedPipeConfig</PipeMonitoringConfig>` |
| **Hash Algorithms**          | `<HashAlgorithms>`      | `xs:string` | Comma-separated list of hash algorithms or `*` for all. Default: SHA1.      | `<HashAlgorithms>SHA256,SHA1</HashAlgorithms>`   |
| **DNS Lookup**               | `<DnsLookup>`           | `xs:string` | Enables/disables reverse DNS lookups for network events. Default: `true`.   | `<DnsLookup>false</DnsLookup>`                    |
| **Process Access Config**    | `<ProcessAccessConfig>` | `xs:string` | Process access configuration string. Format not defined in schema.          | `<ProcessAccessConfig>DetailedProcessAccess</ProcessAccessConfig>` |
| **Check Revocation**         | `<CheckRevocation>`     | Empty Tag  | Disables certificate revocation checking. Presence of tag **disables** checking. Default: Enabled. | `<CheckRevocation/>`                           |
| **Field Sizes Configuration**| `<FieldSizes>`          | `xs:string` | Field size limits configuration string. Format not defined in schema.         | `<FieldSizes>LargeFields</FieldSizes>`             |

**XML Example of Global Configuration Entries:**

```xml
<Sysmon schemaversion="4.90">
    <HashAlgorithms>SHA256</HashAlgorithms>
    <ArchiveDirectory>E:\SysmonFileArchive</ArchiveDirectory>
    <CaptureClipboard/>
    <DnsLookup>false</DnsLookup>
</Sysmon>
```

## 4.  Rule Groups (`<RuleGroup>`) in XML

`<RuleGroup>` elements are used within the `<EventFiltering>` section to logically group rules and event filters.

**XML Attributes for `<RuleGroup>`:**

| Attribute         | Required? | Values        | Description                                                                  | XML Example                                     |
| :---------------- | :-------- | :------------ | :--------------------------------------------------------------------------- | :---------------------------------------------- |
| `groupRelation`   | Yes       | `"and"`, `"or"` | Specifies how rules/filters within the group are combined: "and" (all must match), "or" (any can match). | `<RuleGroup name="Network Checks" groupRelation="or">` |
| `name`            | No        | String        | Descriptive name for the RuleGroup (for organization).                       | `<RuleGroup name="Suspicious Processes" ...>`   |

**XML Content for `<RuleGroup>`:**

`<RuleGroup>` can contain either:

*   **`<Rule>` elements:** To define individual rules within the group.
*   **Event Filtering Entries:**  Directly embed event filters (e.g., `<ProcessCreate>`) within the group.

**XML Example of `<RuleGroup>` with nested rules and event filters:**

```xml
<EventFiltering>
    <RuleGroup name="Malware Indicators" groupRelation="or">
        <RuleGroup name="Process Injection Checks" groupRelation="and">
            <Rule name="Remote Thread to LSASS">
                <CreateRemoteThread>
                    <TargetImage condition="image">lsass.exe</TargetImage>
                </CreateRemoteThread>
            </Rule>
            <Rule name="Process Access to LSASS">
                <ProcessAccess>
                    <TargetImage condition="image">lsass.exe</TargetImage>
                </ProcessAccess>
            </Rule>
        </RuleGroup>
        <NetworkConnect>
            <Rule name="Suspicious Ports">
                <DestinationPort condition="less than">1024</DestinationPort>
            </Rule>
        </NetworkConnect>
    </RuleGroup>
</EventFiltering>
```

## 5. Rules (`<Rule>`) in XML

`<Rule>` elements define specific filtering conditions and are used within Event Filtering Entries or RuleGroups.

**XML Attributes for `<Rule>`:**

| Attribute         | Required? | Values        | Description                                                                  | XML Example                                   |
| :---------------- | :-------- | :------------ | :--------------------------------------------------------------------------- | :-------------------------------------------- |
| `groupRelation`   | No        | `"and"`, `"or"` | Specifies how conditions within the rule are combined. Default: `"or"`.        | `<Rule name="Specific Image" groupRelation="and">` |
| `name`            | No        | String        | Descriptive name for the Rule (for organization).                            | `<Rule name="Monitor PowerShell" ...>`        |

**XML Content for `<Rule>`:**

`<Rule>` contains a choice of condition elements that are relevant to the event type where the rule is applied. See section 7 for condition elements per event type.

**XML Example of `<Rule>` with "and" `groupRelation` and multiple conditions:**

```xml
<ProcessCreate>
    <Rule name="Specific Process and User" groupRelation="and">
        <Image condition="image">C:\Tools\Suspicious.exe</Image>
        <User condition="is not">SYSTEM</User>
    </Rule>
</ProcessCreate>
```

## 6. Event Filtering Entries (XML elements like `<ProcessCreate>`, `<NetworkConnect>`)

Event Filtering Entries are XML elements that correspond to specific Sysmon Event IDs. They are used within `<EventFiltering>` or `<RuleGroup>` to define filters for those event types.

**Common XML Attributes for Event Filtering Entries:**

| Attribute     | Required? | Values        | Description                                                                                    | XML Example                                    |
| :------------ | :-------- | :------------ | :--------------------------------------------------------------------------------------------- | :--------------------------------------------- |
| `onmatch`     | No        | `"include"`, `"exclude"` | Action to take when a rule within this filter matches.                                     | `<ProcessCreate onmatch="include">`            |
| `default`     | No        | `"include"`, `"exclude"` | Default action if no rule within this filter matches. Default is often "exclude" if omitted. | `<NetworkConnect default="exclude">`          |

**XML Content for Event Filtering Entries:**

Each Entry can contain:

*   **`<Rule>` elements:** To define complex filtering rules.
*   **Condition elements (directly):**  For simpler conditions directly within the event filter tag.

**XML Example of `<NetworkConnect>` Entry with rules and direct condition:**

```xml
<EventFiltering>
    <NetworkConnect onmatch="include" default="exclude">
        <Rule name="Monitor Port 80 and 443">
            <DestinationPort condition="is any">80;443</DestinationPort>
        </Rule>
        <DestinationIp condition="not begin with">192.168.</DestinationIp> <!- - Direct Condition -->
    </NetworkConnect>
</EventFiltering>
```

## 7. Condition Types and Condition Elements in XML

### 7.1. Condition Types (`ConditionType` attribute)

The `condition` attribute, used within condition elements, specifies the type of comparison.

| Condition Type     | XML Value              | Description                                                                  | XML Example                                          |
| :------------------ | :--------------------- | :--------------------------------------------------------------------------- | :--------------------------------------------------- |
| **Is (Equals)**     | `"is"` (or omitted)    | Exact match (case-insensitive). Default if `condition` attribute is absent.     | `<Image condition="is">powershell.exe</Image>`      |
| **Is Not (Not Equals)**| `"is not"`             | Not an exact match (case-insensitive).                                         | `<User condition="is not">SYSTEM</User>`            |
| **Contains**        | `"contains"`           | Property contains the value (case-insensitive).                               | `<CommandLine condition="contains">evil.ps1</CommandLine>` |
| **Contains Any**    | `"contains any"`       | Property contains any of the semicolon-delimited values (case-insensitive).     | `<Image condition="contains any">cmd.exe;powershell.exe</Image>` |
| **Is Any**          | `"is any"`             | Property is one of the semicolon-delimited values (case-insensitive).           | `<DestinationPort condition="is any">80;443</DestinationPort>` |
| **Contains All**    | `"contains all"`       | Property contains all of the semicolon-delimited values (case-insensitive).     | `<Hashes condition="contains all">MD5=...,SHA256=...</Hashes>` |
| **Excludes**        | `"excludes"`           | Property does not contain the value (case-insensitive).                         | `<Image condition="excludes">unwanted.exe</Image>`   |
| **Excludes Any**    | `"excludes any"`       | Property does not contain one or more of the semicolon-delimited values (case-insensitive). | `<Image condition="excludes any">bad1.exe;bad2.exe</Image>` |
| **Excludes All**    | `"excludes all"`       | Property does not contain any of the semicolon-delimited values (case-insensitive). | `<Image condition="excludes all">good1.exe;good2.exe</Image>` |
| **Begin With**      | `"begin with"`         | Property starts with the value (case-insensitive).                             | `<Image condition="begin with">C:\Windows\</Image>` |
| **Not Begin With**  | `"not begin with"`     | Property does not start with the value (case-insensitive).                         | `<Image condition="not begin with">C:\Temp\</Image>` |
| **End With**        | `"end with"`           | Property ends with the value (case-insensitive).                               | `<Image condition="end with">.exe</Image>`          |
| **Not End With**    | `"not end with"`       | Property does not end with the value (case-insensitive).                           | `<Image condition="not end with">.dll</Image>`      |
| **Less Than**       | `"less than"`          | Lexicographical comparison is less than zero (case-insensitive).               | `<DestinationPort condition="less than">1024</DestinationPort>` |
| **More Than**       | `"more than"`          | Lexicographical comparison is more than zero (case-insensitive).                | `<ProcessId condition="more than">1000</ProcessId>`  |
| **Image Match**     | `"image"`              | Matches image path (full path or just image name, case-insensitive).             | `<Image condition="image">lsass.exe</Image>`         |

### 7.2. Condition Elements per Event Filtering Entry

The following tables list the available condition elements (XML tags) for each Event Filtering Entry type.  These elements are used within `<Rule>` or directly within the Event Filtering Entry.

**(Note:  `RuleName`, `UtcTime`, `ProcessGuid`, `ProcessId`, `Image`, `User` are frequently available. Only listing the more unique or specific condition elements for each event type in tables for brevity. Refer back to section 7.1 for `ConditionType` options applicable to these elements.)**

#### `<ProcessCreate>` (Event ID 1) Condition Elements

| XML Tag               | Type       | Description                                                                | XML Example                                                |
| :-------------------- | :--------- | :------------------------------------------------------------------------- | :--------------------------------------------------------- |
| `<FileVersion>`       | `xs:string` | Process file version.                                                      | `<FileVersion condition="is">10.0.19041.1</FileVersion>`     |
| `<Description>`       | `xs:string` | Process description from file metadata.                                    | `<Description condition="contains">Malicious Tool</Description>` |
| `<Product>`           | `xs:string` | Product name from file metadata.                                           | `<Product condition="is">SuspiciousApp</Product>`           |
| `<Company>`           | `xs:string` | Company name from file metadata.                                           | `<Company condition="is">Evil Corp</Company>`                |
| `<OriginalFileName>`  | `xs:string` | Original filename from file metadata.                                      | `<OriginalFileName condition="end with">.exe</OriginalFileName>` |
| `<CommandLine>`       | `xs:string` | Full command line used to start the process.                               | `<CommandLine condition="contains">-flag</CommandLine>`     |
| `<CurrentDirectory>`  | `xs:string` | Working directory of the process.                                          | `<CurrentDirectory condition="begin with">C:\Temp</CurrentDirectory>` |
| `<LogonGuid>`         | `xs:string` | GUID of the logon session.                                                  | `<LogonGuid condition="is">...</LogonGuid>`                 |
| `<LogonId>`           | `xs:string` | ID of the logon session.                                                    | `<LogonId condition="is">12345</LogonId>`                   |
| `<TerminalSessionId>` | `xs:string` | Terminal session ID.                                                        | `<TerminalSessionId condition="is">1</TerminalSessionId>`     |
| `<IntegrityLevel>`    | `xs:string` | Process integrity level (e.g., "High", "Medium", "Low").                    | `<IntegrityLevel condition="is">Low</IntegrityLevel>`       |
| `<Hashes>`            | `xs:string` | File hashes (algorithms configured via `<HashAlgorithms>`). Format: `ALG=hash`. | `<Hashes condition="contains">SHA256=...</Hashes>`          |
| `<ParentProcessGuid>` | `xs:string` | GUID of the parent process.                                                 | `<ParentProcessGuid condition="is">...</ParentProcessGuid>`   |
| `<ParentProcessId>`   | `xs:string` | ID of the parent process.                                                   | `<ParentProcessId condition="is">54321</ParentProcessId>`     |
| `<ParentImage>`       | `xs:string` | Image path of the parent process.                                          | `<ParentImage condition="image">explorer.exe</ParentImage>`    |
| `<ParentCommandLine>` | `xs:string` | Command line of the parent process.                                        | `<ParentCommandLine condition="contains">parent-flag</ParentCommandLine>` |
| `<ParentUser>`        | `xs:string` | User account of the parent process.                                        | `<ParentUser condition="is">DOMAIN\User</ParentUser>`       |

**(Tables for other Event Filtering Entries - `<FileCreateTime>`, `<NetworkConnect>`, `<ProcessTerminate>`, `<DriverLoad>`, `<ImageLoad>`, `<CreateRemoteThread>`, `<RawAccessRead>`, `<ProcessAccess>`, `<FileCreate>`, `<RegistryEvent>`, `<FileCreateStreamHash>`, `<PipeEvent>`, `<WmiEventFilter>`, `<WmiEventConsumer>`, `<WmiEventBinding>`, `<DnsQuery>`, `<FileDelete>`, `<ClipboardChange>`, `<ProcessTampering>`, `<FileDeleteDetected>`, `<FileBlockExecutable>`, `<FileBlockShredding>`, `<FileExecutableDetected>` would follow a similar format, listing their respective XML condition elements, types, descriptions, and XML examples.  For brevity, these detailed tables are omitted here but would be included in a full comprehensive guide.  Refer to the XSD for the complete list of condition elements for each event type.)**
