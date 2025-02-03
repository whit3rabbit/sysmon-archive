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

### `<FileCreateTime>` (Event ID 2) Condition Elements

| XML Tag                     | Type       | Description                                                               | XML Example                                                   |
| :-------------------------- | :--------- | :------------------------------------------------------------------------ | :------------------------------------------------------------ |
| `<TargetFilename>`          | `xs:string` | The filename whose creation time was changed.                               | `<TargetFilename condition="end with">.tmp</TargetFilename>`    |
| `<CreationUtcTime>`         | `xs:string` | New creation time in UTC.                                                | `<CreationUtcTime condition="more than">...</CreationUtcTime>` |
| `<PreviousCreationUtcTime>` | `xs:string` | Previous creation time in UTC.                                             | `<PreviousCreationUtcTime condition="less than">...</PreviousCreationUtcTime>` |

**XML Example for `<FileCreateTime>`:**

```xml
<FileCreateTime onmatch="include">
    <Rule name="Monitor Temp File Creation Time Changes">
        <TargetFilename condition="contains">C:\Temp\</TargetFilename>
    </Rule>
</FileCreateTime>
```

### `<NetworkConnect>` (Event ID 3) Condition Elements

| XML Tag                 | Type       | Description                                                                 | XML Example                                                        |
| :---------------------- | :--------- | :-------------------------------------------------------------------------- | :----------------------------------------------------------------- |
| `<Protocol>`            | `xs:string` | Network protocol (e.g., tcp, udp).                                          | `<Protocol condition="is">udp</Protocol>`                         |
| `<Initiated>`           | `xs:string` | "true" if the connection was initiated by the monitored process.           | `<Initiated condition="is">true</Initiated>`                       |
| `<SourceIsIpv6>`        | `xs:string` | "true" if the source IP address is IPv6.                                    | `<SourceIsIpv6 condition="is">false</SourceIsIpv6>`              |
| `<SourceIp>`            | `xs:string` | Source IP address.                                                           | `<SourceIp condition="begin with">192.168.</SourceIp>`             |
| `<SourceHostname>`      | `xs:string` | Source hostname (if DNS lookup is enabled and successful).                   | `<SourceHostname condition="contains">domain.local</SourceHostname>` |
| `<SourcePort>`          | `xs:string` | Source port number.                                                          | `<SourcePort condition="less than">1024</SourcePort>`             |
| `<SourcePortName>`      | `xs:string` | Source port name (e.g., "http", "https") if known.                          | `<SourcePortName condition="is">ephemeral</SourcePortName>`       |
| `<DestinationIsIpv6>`   | `xs:string` | "true" if the destination IP address is IPv6.                               | `<DestinationIsIpv6 condition="is">true</DestinationIsIpv6>`       |
| `<DestinationIp>`       | `xs:string` | Destination IP address.                                                      | `<DestinationIp condition="is">8.8.8.8</DestinationIp>`           |
| `<DestinationHostname>` | `xs:string` | Destination hostname (if DNS lookup is enabled and successful).              | `<DestinationHostname condition="end with">.example.com</DestinationHostname>` |
| `<DestinationPort>`     | `xs:string` | Destination port number.                                                     | `<DestinationPort condition="is">80</DestinationPort>`              |
| `<DestinationPortName>` | `xs:string` | Destination port name (e.g., "http", "https") if known.                     | `<DestinationPortName condition="is">http</DestinationPortName>`      |

**XML Example for `<NetworkConnect>`:**

```xml
<NetworkConnect onmatch="exclude">
    <Rule name="Exclude Outbound Port 53 and Local Networks">
        <DestinationPort condition="is">53</DestinationPort>
        <DestinationIp condition="begin with any">192.168.;10.</DestinationIp>
    </Rule>
</NetworkConnect>
```

### Event ID 4: Sysmon service state changed

### `<ProcessTerminate>` (Event ID 5) Condition Elements

*No unique condition elements beyond the common ones (RuleName, UtcTime, ProcessGuid, ProcessId, Image, User).*

**XML Example for `<ProcessTerminate>`:**

```xml
<ProcessTerminate onmatch="include">
    <Rule name="Monitor Process Termination of Critical Services">
        <Image condition="image">svchost.exe</Image>
    </Rule>
</ProcessTerminate>
```

### `<DriverLoad>` (Event ID 6) Condition Elements

| XML Tag             | Type       | Description                                                                 | XML Example                                              |
| :------------------ | :--------- | :-------------------------------------------------------------------------- | :------------------------------------------------------- |
| `<ImageLoaded>`     | `xs:string` | Path to the driver image loaded.                                            | `<ImageLoaded condition="end with">.sys</ImageLoaded>`     |
| `<Hashes>`          | `xs:string` | Driver file hashes (algorithms configured via `<HashAlgorithms>`). Format: `ALG=hash`. | `<Hashes condition="contains">SHA1=...</Hashes>`        |
| `<Signed>`          | `xs:string` | "true" if the driver image is digitally signed.                              | `<Signed condition="is">true</Signed>`                     |
| `<Signature>`       | `xs:string` | Digital signature of the driver image.                                       | `<Signature condition="contains">...</Signature>`          |
| `<SignatureStatus>` | `xs:string` | Status of the digital signature validation.                                  | `<SignatureStatus condition="is not">Valid</SignatureStatus>` |

**XML Example for `<DriverLoad>`:**

```xml
<DriverLoad onmatch="exclude">
    <Rule name="Exclude Microsoft Signed Drivers">
        <Signed condition="is">true</Signed>
        <Signature condition="contains">Microsoft</Signature>
    </Rule>
</DriverLoad>
```

### `<ImageLoad>` (Event ID 7) Condition Elements

| XML Tag             | Type       | Description                                                                 | XML Example                                                    |
| :------------------ | :--------- | :-------------------------------------------------------------------------- | :------------------------------------------------------------- |
| `<ImageLoaded>`     | `xs:string` | Path to the image loaded into a process.                                     | `<ImageLoaded condition="end with">.dll</ImageLoaded>`         |
| `<FileVersion>`     | `xs:string` | Image file version.                                                         | `<FileVersion condition="is">...</FileVersion>`                |
| `<Description>`     | `xs:string` | Image description from file metadata.                                       | `<Description condition="contains">Library</Description>`        |
| `<Product>`         | `xs:string` | Product name from file metadata.                                            | `<Product condition="is">MyProduct</Product>`                 |
| `<Company>`         | `xs:string` | Company name from file metadata.                                            | `<Company condition="is">Unknown Publisher</Company>`          |
| `<OriginalFileName>`| `xs:string` | Original filename from file metadata.                                      | `<OriginalFileName condition="end with">.dll</OriginalFileName>` |
| `<Hashes>`          | `xs:string` | Image file hashes (algorithms configured via `<HashAlgorithms>`). Format: `ALG=hash`. | `<Hashes condition="contains">MD5=...</Hashes>`              |
| `<Signed>`          | `xs:string` | "true" if the image is digitally signed.                                      | `<Signed condition="is">false</Signed>`                        |
| `<Signature>`       | `xs:string` | Digital signature of the image.                                            | `<Signature condition="contains">...</Signature>`             |
| `<SignatureStatus>` | `xs:string` | Status of the digital signature validation.                                   | `<SignatureStatus condition="is not">Valid</SignatureStatus>`    |

**XML Example for `<ImageLoad>`:**

```xml
<ImageLoad onmatch="include">
    <Rule name="Monitor Loads of Unsigned DLLs">
        <Signed condition="is">false</Signed>
        <ImageLoaded condition="end with">.dll</ImageLoaded>
    </Rule>
</ImageLoad>
```

### `<CreateRemoteThread>` (Event ID 8) Condition Elements

| XML Tag             | Type       | Description                                                                 | XML Example                                                     |
| :------------------ | :--------- | :-------------------------------------------------------------------------- | :-------------------------------------------------------------- |
| `<SourceProcessGuid>`| `xs:string` | GUID of the process initiating the remote thread creation.                  | `<SourceProcessGuid condition="is">...</SourceProcessGuid>`    |
| `<SourceProcessId>`  | `xs:string` | ID of the process initiating the remote thread creation.                    | `<SourceProcessId condition="is">1234</SourceProcessId>`       |
| `<SourceImage>`      | `xs:string` | Image path of the process initiating the remote thread creation.             | `<SourceImage condition="image">malware.exe</SourceImage>`       |
| `<TargetProcessGuid>`| `xs:string` | GUID of the target process where the thread is created.                      | `<TargetProcessGuid condition="is">...</TargetProcessGuid>`    |
| `<TargetProcessId>`  | `xs:string` | ID of the target process where the thread is created.                        | `<TargetProcessId condition="is">5678</TargetProcessId>`       |
| `<TargetImage>`      | `xs:string` | Image path of the target process.                                           | `<TargetImage condition="image">lsass.exe</TargetImage>`       |
| `<NewThreadId>`      | `xs:string` | ID of the newly created thread.                                             | `<NewThreadId condition="is">91011</NewThreadId>`             |
| `<StartAddress>`     | `xs:string` | Starting address of the remote thread.                                      | `<StartAddress condition="contains">...</StartAddress>`        |
| `<StartModule>`      | `xs:string` | Module where the thread starts execution (if known).                         | `<StartModule condition="contains">ntdll.dll</StartModule>`      |
| `<StartFunction>`    | `xs:string` | Function where the thread starts execution (if known).                       | `<StartFunction condition="contains">NtCreateThreadEx</StartFunction>` |
| `<SourceUser>`       | `xs:string` | User account of the source process.                                         | `<SourceUser condition="is">DOMAIN\User</SourceUser>`         |
| `<TargetUser>`       | `xs:string` | User account of the target process.                                         | `<TargetUser condition="is">SYSTEM</TargetUser>`             |

**XML Example for `<CreateRemoteThread>`:**

```xml
<CreateRemoteThread onmatch="include">
    <Rule name="Monitor Remote Thread to LSASS from Suspicious Process">
        <TargetImage condition="image">lsass.exe</TargetImage>
        <SourceImage condition="contains any">malware.exe;badprocess.exe</SourceImage>
    </Rule>
</CreateRemoteThread>
```

### `<RawAccessRead>` (Event ID 9) Condition Elements

| XML Tag         | Type       | Description                                                                 | XML Example                                            |
| :-------------- | :--------- | :-------------------------------------------------------------------------- | :----------------------------------------------------- |
| `<Device>`        | `xs:string` | Device object accessed via raw access read.                                  | `<Device condition="contains">\\Device\\HarddiskVolume</Device>` |

**XML Example for `<RawAccessRead>`:**

```xml
<RawAccessRead onmatch="include">
    <Rule name="Monitor Raw Access to Disk Devices">
        <Device condition="begin with">\\Device\\Harddisk</Device>
    </Rule>
</RawAccessRead>
```

### `<ProcessAccess>` (Event ID 10) Condition Elements

| XML Tag             | Type       | Description                                                                 | XML Example                                                |
| :------------------ | :--------- | :-------------------------------------------------------------------------- | :--------------------------------------------------------- |
| `<SourceProcessGUID>`| `xs:string` | GUID of the process initiating the process access.                          | `<SourceProcessGUID condition="is">...</SourceProcessGUID>`   |
| `<SourceThreadId>`   | `xs:string` | ID of the thread in the source process initiating the access.                | `<SourceThreadId condition="is">12345</SourceThreadId>`     |
| `<TargetProcessGUID>`| `xs:string` | GUID of the target process being accessed.                                  | `<TargetProcessGUID condition="is">...</TargetProcessGUID>`   |
| `<GrantedAccess>`     | `xs:string` | Granted access mask (hexadecimal representation of access rights).           | `<GrantedAccess condition="contains">0x1FFFFF</GrantedAccess>` |
| `<CallTrace>`       | `xs:string` | Call trace leading to the process access event.                              | `<CallTrace condition="contains">ntdll.dll</CallTrace>`      |

**XML Example for `<ProcessAccess>`:**

```xml
<ProcessAccess onmatch="include">
    <Rule name="Monitor Process Access to LSASS with Full Access">
        <TargetImage condition="image">lsass.exe</TargetImage>
        <GrantedAccess condition="is">0x1FFFFF</GrantedAccess>
    </Rule>
</ProcessAccess>
```

### `<FileCreate>` (Event ID 11) Condition Elements

| XML Tag             | Type       | Description                                                                 | XML Example                                               |
| :------------------ | :--------- | :-------------------------------------------------------------------------- | :-------------------------------------------------------- |
| `<TargetFilename>`    | `xs:string` | Path of the file created.                                                   | `<TargetFilename condition="end with">.log</TargetFilename>` |
| `<CreationUtcTime>`   | `xs:string` | Creation time of the file in UTC.                                            | `<CreationUtcTime condition="more than">...</CreationUtcTime>` |

**XML Example for `<FileCreate>`:**

```xml
<FileCreate onmatch="include">
    <Rule name="Monitor Creation of Executables in Temp">
        <TargetFilename condition="contains">C:\Temp\</TargetFilename>
        <TargetFilename condition="end with any">.exe;.bat;.com</TargetFilename>
    </Rule>
</FileCreate>
```

### `<RegistryEvent>` (Event IDs 12, 13, 14) Condition Elements

| XML Tag         | Type       | Description                                                                 | XML Example                                              |
| :-------------- | :--------- | :-------------------------------------------------------------------------- | :------------------------------------------------------- |
| `<EventType>`     | `xs:string` | Type of registry event (e.g., "CreateKey", "SetValue", "DeleteValue").     | `<EventType condition="is">SetValue</EventType>`         |
| `<TargetObject>`  | `xs:string` | Registry object (key or value) targeted by the event.                       | `<TargetObject condition="begin with">HKLM\Software</TargetObject>` |
| `<Details>`       | `xs:string` | Details specific to the event type (e.g., new value data).                  | `<Details condition="contains">malware.example.com</Details>` |
| `<NewName>`       | `xs:string` | New name in case of a rename operation.                                    | `<NewName condition="end with">NewRegistryKeyName</NewName>` |

**XML Example for `<RegistryEvent>`:**

```xml
<RegistryEvent onmatch="include">
    <Rule name="Monitor Registry Run Keys Modifications">
        <TargetObject condition="begin with any">
            HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run;
            HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        </TargetObject>
        <EventType condition="is any">SetValue;CreateKey</EventType>
    </Rule>
</RegistryEvent>
```

### `<FileCreateStreamHash>` (Event ID 15) Condition Elements

| XML Tag             | Type       | Description                                                                 | XML Example                                                   |
| :------------------ | :--------- | :-------------------------------------------------------------------------- | :------------------------------------------------------------ |
| `<TargetFilename>`    | `xs:string` | Path of the file for which stream hash is calculated.                       | `<TargetFilename condition="end with">.exe</TargetFilename>`    |
| `<CreationUtcTime>`   | `xs:string` | Creation time of the file in UTC.                                            | `<CreationUtcTime condition="more than">...</CreationUtcTime>` |
| `<Hash>`              | `xs:string` | Hash of the file stream (algorithms configured via `<HashAlgorithms>`). Format: `ALG=hash`. | `<Hash condition="contains">SHA256=...</Hash>`              |
| `<Contents>`          | `xs:string` | First 1024 bytes of the file content (might be truncated).                 | `<Contents condition="contains">MZ</Contents>`               |

**XML Example for `<FileCreateStreamHash>`:**

```xml
<FileCreateStreamHash onmatch="include">
    <Rule name="Monitor Executable File Stream Hash Creation">
        <TargetFilename condition="end with any">.exe;.dll</TargetFilename>
        <Hash condition="excludes">SHA1=...</Hash> <!- - Example to exclude a known good hash -->
    </Rule>
</FileCreateStreamHash>
```

### `<PipeEvent>` (Event IDs 17, 18) Condition Elements

| XML Tag         | Type       | Description                                                                 | XML Example                                          |
| :-------------- | :--------- | :-------------------------------------------------------------------------- | :--------------------------------------------------- |
| `<EventType>`     | `xs:string` | Type of pipe event ("Create" or "Connect").                                 | `<EventType condition="is">Create</EventType>`       |
| `<PipeName>`      | `xs:string` | Name of the named pipe.                                                     | `<PipeName condition="contains">malwarepipe</PipeName>` |

**XML Example for `<PipeEvent>`:**

```xml
<PipeEvent onmatch="include">
    <Rule name="Monitor Creation of Specific Named Pipes">
        <EventType condition="is">Create</EventType>
        <PipeName condition="contains any">evilpipe;suspiciouspipe</PipeName>
    </Rule>
</PipeEvent>
```

### `<WmiEventFilter>` (Event ID 19) Condition Elements

| XML Tag           | Type       | Description                                                                 | XML Example                                            |
| :---------------- | :--------- | :-------------------------------------------------------------------------- | :----------------------------------------------------- |
| `<EventType>`       | `xs:string` | Type of WMI event filter activity (e.g., "create", "delete", "modify").     | `<EventType condition="is">Create</EventType>`         |
| `<Operation>`       | `xs:string` | Specific operation within the event (e.g., "FilterBinding", "ConsumerBinding"). | `<Operation condition="is">FilterBinding</Operation>`   |
| `<EventNamespace>`  | `xs:string` | WMI namespace where the filter is registered.                               | `<EventNamespace condition="is">root\cimv2</EventNamespace>` |
| `<Name>`            | `xs:string` | Name of the WMI event filter.                                               | `<Name condition="contains">SuspiciousFilter</Name>`     |
| `<Query>`           | `xs:string` | WQL query associated with the WMI event filter.                             | `<Query condition="contains">Process Create</Query>`      |

**XML Example for `<WmiEventFilter>`:**

```xml
<WmiEventFilter onmatch="include">
    <Rule name="Monitor Creation of WMI Event Filters with Process Creation Query">
        <EventType condition="is">Create</EventType>
        <Query condition="contains">Process Create</Query>
    </Rule>
</WmiEventFilter>
```

### `<WmiEventConsumer>` (Event ID 20) Condition Elements

| XML Tag           | Type       | Description                                                                 | XML Example                                             |
| :---------------- | :--------- | :-------------------------------------------------------------------------- | :------------------------------------------------------ |
| `<EventType>`       | `xs:string` | Type of WMI event consumer activity (e.g., "create", "delete", "modify").   | `<EventType condition="is">Create</EventType>`          |
| `<Operation>`       | `xs:string` | Specific operation within the event (e.g., "FilterBinding", "ConsumerBinding"). | `<Operation condition="is">ConsumerBinding</Operation>`    |
| `<Name>`            | `xs:string` | Name of the WMI event consumer.                                             | `<Name condition="contains">SuspiciousConsumer</Name>`    |
| `<Type>`            | `xs:string` | Type of WMI event consumer (e.g., "ActiveScriptConsumer", "CommandLineEventConsumer"). | `<Type condition="is">CommandLineEventConsumer</Type>` |
| `<Destination>`     | `xs:string` | Destination associated with the consumer (e.g., script path, command line). | `<Destination condition="contains">evil.vbs</Destination>`  |

**XML Example for `<WmiEventConsumer>`:**

```xml
<WmiEventConsumer onmatch="include">
    <Rule name="Monitor Creation of CommandLineEventConsumers with Suspicious Destinations">
        <EventType condition="is">Create</EventType>
        <Type condition="is">CommandLineEventConsumer</Type>
        <Destination condition="end with any">.vbs;.js;.ps1</Destination>
    </Rule>
</WmiEventConsumer>
```

### `<WmiEventBinding>` (Event ID 21) Condition Elements

| XML Tag         | Type       | Description                                                                 | XML Example                                           |
| :-------------- | :--------- | :-------------------------------------------------------------------------- | :---------------------------------------------------- |
| `<EventType>`     | `xs:string` | Type of WMI event binding activity (e.g., "create", "delete", "modify").   | `<EventType condition="is">Create</EventType>`        |
| `<Operation>`     | `xs:string` | Specific operation within the event (e.g., "FilterBinding", "ConsumerBinding"). | `<Operation condition="is">FilterBinding</Operation>`  |
| `<Consumer>`      | `xs:string` | Name of the WMI event consumer being bound.                                 | `<Consumer condition="contains">SuspiciousConsumer</Consumer>` |
| `<Filter>`        | `xs:string` | Name of the WMI event filter being bound.                                   | `<Filter condition="contains">SuspiciousFilter</Filter>`   |

**XML Example for `<WmiEventBinding>`:**

```xml
<WmiEventBinding onmatch="include">
    <Rule name="Monitor WMI Event Binding to Suspicious Consumer/Filter">
        <EventType condition="is">Create</EventType>
        <Consumer condition="contains">SuspiciousConsumer</Consumer>
        <Filter condition="contains">SuspiciousFilter</Filter>
    </Rule>
</WmiEventBinding>
```

### `<DnsQuery>` (Event ID 22) Condition Elements

| XML Tag          | Type       | Description                                                                 | XML Example                                            |
| :--------------- | :--------- | :-------------------------------------------------------------------------- | :----------------------------------------------------- |
| `<QueryName>`      | `xs:string` | DNS query name.                                                             | `<QueryName condition="end with">.malware.com</QueryName>` |
| `<QueryStatus>`    | `xs:string` | DNS query status code (e.g., "0" for success).                             | `<QueryStatus condition="is">0</QueryStatus>`           |
| `<QueryResults>`   | `xs:string` | DNS query results (IP addresses, hostnames).                               | `<QueryResults condition="contains">8.8.8.8</QueryResults>` |

**XML Example for `<DnsQuery>`:**

```xml
<DnsQuery onmatch="include">
    <Rule name="Monitor DNS Queries for Suspicious Domains">
        <QueryName condition="end with any">.xyz;.top;.bit</QueryName>
    </Rule>
</DnsQuery>
```

### `<FileDelete>` (Event ID 23) Condition Elements

| XML Tag             | Type       | Description                                                                 | XML Example                                                   |
| :------------------ | :--------- | :-------------------------------------------------------------------------- | :------------------------------------------------------------ |
| `<TargetFilename>`    | `xs:string` | Path of the file deleted (and archived).                                    | `<TargetFilename condition="end with">.exe</TargetFilename>`    |
| `<Hashes>`          | `xs:string` | File hashes of the deleted file (algorithms configured via `<HashAlgorithms>`). Format: `ALG=hash`. | `<Hashes condition="contains">SHA256=...</Hashes>`              |
| `<IsExecutable>`    | `xs:string` | "true" if the deleted file was considered executable.                        | `<IsExecutable condition="is">true</IsExecutable>`            |
| `<Archived>`        | `xs:string` | "true" if the deleted file was successfully archived.                       | `<Archived condition="is">true</Archived>`                  |

**XML Example for `<FileDelete>`:**

```xml
<FileDelete onmatch="include">
    <Rule name="Monitor Deletion of Executables from Temp">
        <TargetFilename condition="contains">C:\Temp\</TargetFilename>
        <TargetFilename condition="end with any">.exe;.dll</TargetFilename>
        <IsExecutable condition="is">true</IsExecutable>
    </Rule>
</FileDelete>
```

### `<ClipboardChange>` (Event ID 24) Condition Elements

| XML Tag         | Type       | Description                                                                 | XML Example                                            |
| :-------------- | :--------- | :-------------------------------------------------------------------------- | :----------------------------------------------------- |
| `<Session>`       | `xs:string` | Terminal session ID where the clipboard change occurred.                    | `<Session condition="is">1</Session>`                   |
| `<ClientInfo>`    | `xs:string` | Client information related to the clipboard operation (process name, etc.). | `<ClientInfo condition="contains">chrome.exe</ClientInfo>` |
| `<Hashes>`        | `xs:string` | Hashes of the process involved in the clipboard change (algorithms configured via `<HashAlgorithms>`). Format: `ALG=hash`. | `<Hashes condition="contains">MD5=...</Hashes>`        |
| `<Archived>`      | `xs:string` | "true" if clipboard content archiving is enabled (likely always true if event is generated). | `<Archived condition="is">true</Archived>`             |

**XML Example for `<ClipboardChange>`:**

```xml
<ClipboardChange onmatch="exclude">
    <Rule name="Exclude Clipboard Changes from Known Processes">
        <ClientInfo condition="contains any">explorer.exe;chrome.exe;firefox.exe</ClientInfo>
    </Rule>
</ClipboardChange>
```

### `<ProcessTampering>` (Event ID 25) Condition Elements

| XML Tag                  | Type       | Description                                                                 | XML Example                                                     |
| :----------------------- | :--------- | :-------------------------------------------------------------------------- | :-------------------------------------------------------------- |
| `<Type>`                   | `xs:string` | Type of process tampering (e.g., "Image modification", "Handle duplication"). | `<Type condition="is">Image modification</Type>`              |
| `<TargetProcessCommandLine>`| `xs:string` | Command line of the target process being tampered with.                      | `<TargetProcessCommandLine condition="contains">victim.exe</TargetProcessCommandLine>` |
| `<ProcessAccessMask>`      | `xs:string` | Process access mask used in the tampering attempt (hexadecimal).             | `<ProcessAccessMask condition="contains">0x1FFFFF</ProcessAccessMask>` |

**XML Example for `<ProcessTampering>`:**

```xml
<ProcessTampering onmatch="include">
    <Rule name="Monitor Process Tampering of LSASS">
        <TargetImage condition="image">lsass.exe</TargetImage>
        <Type condition="is">Image modification</Type>
    </Rule>
</ProcessTampering>
```

### `<FileDeleteDetected>` (Event ID 26) Condition Elements

| XML Tag             | Type       | Description                                                                 | XML Example                                                   |
| :------------------ | :--------- | :-------------------------------------------------------------------------- | :------------------------------------------------------------ |
| `<TargetFilename>`    | `xs:string` | Path of the file deleted (detection only, not archived).                   | `<TargetFilename condition="end with">.tmp</TargetFilename>`    |
| `<Hashes>`          | `xs:string` | File hashes of the deleted file (algorithms configured via `<HashAlgorithms>`). Format: `ALG=hash`. | `<Hashes condition="contains">SHA256=...</Hashes>`              |
| `<IsExecutable>`    | `xs:string` | "true" if the deleted file was considered executable.                        | `<IsExecutable condition="is">true</IsExecutable>`            |

**XML Example for `<FileDeleteDetected>`:**

```xml
<FileDeleteDetected onmatch="include">
    <Rule name="Monitor Detection of Executable Deletion in Downloads">
        <TargetFilename condition="contains">C:\Users\*\Downloads\</TargetFilename>
        <TargetFilename condition="end with any">.exe;.dll</TargetFilename>
        <IsExecutable condition="is">true</IsExecutable>
    </Rule>
</FileDeleteDetected>
```

### `<FileBlockExecutable>` (Event ID 27) Condition Elements

| XML Tag             | Type       | Description                                                                 | XML Example                                                   |
| :------------------ | :--------- | :-------------------------------------------------------------------------- | :------------------------------------------------------------ |
| `<TargetFilename>`    | `xs:string` | Path of the file blocked from executing.                                    | `<TargetFilename condition="end with">.exe</TargetFilename>`    |
| `<Hashes>`          | `xs:string` | File hashes of the blocked executable (algorithms configured via `<HashAlgorithms>`). Format: `ALG=hash`. | `<Hashes condition="contains">SHA256=...</Hashes>`              |

**XML Example for `<FileBlockExecutable>`:**

```xml
<FileBlockExecutable onmatch="include">
    <Rule name="Monitor Blocking of Executables in Temp">
        <TargetFilename condition="contains">C:\Temp\</TargetFilename>
        <TargetFilename condition="end with any">.exe;.scr</TargetFilename>
    </Rule>
</FileBlockExecutable>
```

### `<FileBlockShredding>` (Event ID 28) Condition Elements

| XML Tag             | Type       | Description                                                                 | XML Example                                                   |
| :------------------ | :--------- | :-------------------------------------------------------------------------- | :------------------------------------------------------------ |
| `<TargetFilename>`    | `xs:string` | Path of the file blocked from shredding/overwriting.                         | `<TargetFilename condition="end with">.sensitive</TargetFilename>` |
| `<Hashes>`          | `xs:string` | File hashes of the file blocked from shredding (algorithms configured via `<HashAlgorithms>`). Format: `ALG=hash`. | `<Hashes condition="contains">SHA256=...</Hashes>`              |
| `<IsExecutable>`    | `xs:string` | "true" if the file blocked from shredding was considered executable.        | `<IsExecutable condition="is">false</IsExecutable>`           |

**XML Example for `<FileBlockShredding>`:**

```xml
<FileBlockShredding onmatch="include">
    <Rule name="Monitor Blocking of Shredding for Document Files">
        <TargetFilename condition="end with any">.doc;.docx;.xls;.xlsx;.ppt;.pptx</TargetFilename>
        <IsExecutable condition="is">false</IsExecutable> <!- - Example to target data files, not executables -->
    </Rule>
</FileBlockShredding>
```

### `<FileExecutableDetected>` (Event ID 29) Condition Elements

| XML Tag             | Type       | Description                                                                 | XML Example                                                   |
| :------------------ | :--------- | :-------------------------------------------------------------------------- | :------------------------------------------------------------ |
| `<TargetFilename>`    | `xs:string` | Path of the file detected as executable (e.g., renamed, downloaded).        | `<TargetFilename condition="end with">.exe</TargetFilename>`    |
| `<Hashes>`          | `xs:string` | File hashes of the detected executable (algorithms configured via `<HashAlgorithms>`). Format: `ALG=hash`. | `<Hashes condition="contains">SHA256=...</Hashes>`              |

**XML Example for `<FileExecutableDetected>`:**

```xml
<FileExecutableDetected onmatch="include">
    <Rule name="Monitor Executables Detected in Downloads Folder">
        <TargetFilename condition="contains">C:\Users\*\Downloads\</TargetFilename>
        <TargetFilename condition="end with any">.exe;.com;.scr</TargetFilename>
    </Rule>
</FileExecutableDetected>
```
