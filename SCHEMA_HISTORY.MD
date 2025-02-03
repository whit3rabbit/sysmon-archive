# Sysmon Schema Version History

## v3.3 to v3.4

- Added support for WMI event monitoring with three new events:
  - Event ID 19: SYSMON_WMI_FILTER - Monitors WMI filter activity
  - Event ID 20: SYSMON_WMI_CONSUMER - Tracks WMI consumer activity
  - Event ID 21: SYSMON_WMI_BINDING - Detects WMI consumer to filter binding

## v3.4 to v4.1

- Updated binary version from 1.01 to 8.00
- Added new configuration options:
  - PrintSchema (-s) option for schema printing
  - DriverName (-d) parameter for driver configuration
- Enhanced process creation monitoring with additional metadata fields:
  - FileVersion
  - Description
  - Product
  - Company
  - OriginalFileName
- Enhanced ImageLoad events with additional metadata fields:
  - FileVersion
  - Description
  - Product
  - Company
  - OriginalFileName
- Added RuleName field to all events for better rule tracking
- Network and Image Load rules are now configurable with -n and -l options

## v4.1 to v4.21

- Updated binary version from 8.00 to 9.10
- Modified command line options:
  - Changed UnInstall (-u) to accept optional arguments
  - Updated DebugMode (-t) to accept optional arguments
- Added new configuration options:
  - DnsQuery (--dns) for DNS monitoring
- Added new filter conditions:
  - "contains any"
  - "contains all"

## v4.21 to v4.22

- Updated binary version from 9.10 to 9.20
- Enhanced filter conditions by adding:
  - "contains any"
  - "contains all"

## v4.22 to v4.40

- Updated binary version from 9.20 to 11.0
- Added new options:
  - ClipboardInstance (-z) for clipboard monitoring
  - ArchiveDirectory (-a) for file archiving
  - CaptureClipboard for clipboard content capture
  - DnsLookup for DNS resolution configuration
- Added new events:
  - Event ID 23: SYSMON_FILE_DELETE - File deletion monitoring with archiving
  - Event ID 24: SYSMON_CLIPBOARD - Clipboard change monitoring
- Added EventType field to pipe events:
  - CREATE_NAMEDPIPE
  - CONNECT_NAMEDPIPE
- Added Contents field to FILE_CREATE_STREAM_HASH event
- Modified file deletion template from "File Delete" to "File Delete archived"

## v4.40 to v4.50

- Updated binary version from 11.0 to 13.0
- Modified CheckRevocation (-r) to accept optional arguments
- Added new event:
  - Event ID 25: SYSMON_PROCESS_IMAGE_TAMPERING - Detects process image tampering
- Changed default rules from "include" to "exclude" for:
  - REG_KEY
  - REG_SETVALUE
  - REG_NAME
  - FILE_CREATE
  - FILE_CREATE_STREAM_HASH
- Added new filter conditions:
  - "excludes any"
  - "excludes all"
  - "is any"

## v4.50 to v4.70

- Updated binary version from 13.0 to 15.0
- Added new command-line option:
  - Service (--service) flag
- Renamed all SYSMON_ event prefixes to SYSMONEVENT_
- Added new filter conditions:
  - "not begin with"
  - "not end with"
- Added Event ID 26: SYSMONEVENT_FILE_DELETE_DETECTED for file deletion logging
- Updated template for **SYSMONEVENT_FILE_DELETE_DETECTED** event from "File Delete" to "File Delete logged"

## v4.70 to v4.81

- Updated binary version from 15.0 to 16.0
- Added new configuration option:
  - FieldSizes for field size configuration
- Enhanced event logging with additional user context:
  - Added User field to many events
  - Added ParentUser field to process creation events
  - Added SourceUser and TargetUser fields to relevant events (CreateRemoteThread, ProcessAccess)
- Added PreviousCreationUtcTime to FILE_TIME event
- Added CreationUtcTime to FILE_CREATE event
- Added SignatureStatus field to IMAGE_LOAD event

## v4.81 to v4.83

- Updated binary version from 16 to 17
- Added new debugging option:
  - BTF (--btf) for enhanced debugging
- Added new events:
  - Event ID 27: SYSMONEVENT_FILE_BLOCK_EXE - Executable file blocking
  - Event ID 28: SYSMONEVENT_FILE_BLOCK_SHREDDING - File shredding prevention with IsExecutable field

## v4.83 to v4.90

- Updated binary version from 17 to 18
- Added new event:
  - Event ID 29: SYSMONEVENT_FILE_EXE_DETECTED - Executable file detection