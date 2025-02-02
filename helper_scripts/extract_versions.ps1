# Get all directories that match the date pattern
$directories = Get-ChildItem -Directory -Path "." -Filter "20*"

# Create a log file for the operation
$logFile = "sysmon_version_processing_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
"Started processing at $(Get-Date)" | Out-File $logFile

# Function to compare versions
function Compare-SysmonVersion {
    param(
        [string]$version,
        [string]$targetVersion
    )
    
    $v1 = [version]($version -replace '^v')
    $v2 = [version]$targetVersion
    return $v1.CompareTo($v2)
}

foreach ($dir in $directories) {
    $needsRename = $true
    $version = $null
    
    # Check if folder is already renamed with version
    if ($dir.Name -match "_v(\d+)_(\d+)$") {
        $needsRename = $false
        $version = "$($matches[1]).$($matches[2])"
        $message = "Processing folder: $($dir.Name), version: $version"
        Write-Host $message -ForegroundColor Yellow
        $message | Out-File $logFile -Append
    }
    
    $sysmonPath = Join-Path $dir.FullName "Sysmon.exe"
    
    if (Test-Path $sysmonPath) {
        try {
            # Format version for schema filename
            $formattedVersion = "{0}_{1:00}" -f $version.Split('.')
            $schemaFile = Join-Path $dir.FullName "v${formattedVersion}_schema.xml"

            # Check if schema file already exists
            if (-not (Test-Path $schemaFile)) {
                # Only try to extract schema if version is 6.0 or higher
                if ((Compare-SysmonVersion -version $version -targetVersion "6.0") -ge 0) {
                    try {
                        $message = "Attempting schema extraction for $($dir.Name)"
                        Write-Host $message
                        $message | Out-File $logFile -Append

                        # Run Sysmon -s
                        $schemaOutput = & $sysmonPath -s 2>&1 | Out-String

                        # Clean up any BOM or special characters at the start
                        $schemaOutput = $schemaOutput -replace '^[\s\x00-\x1F\x7F-\xFF]*', ''

                        # Extract everything from <manifest> to </manifest>
                        if ($schemaOutput -match '(?s)<manifest.*</manifest>') {
                            $xmlContent = $matches[0]
                            
                            # Clean up the XML content
                            $xmlContent = $xmlContent.Trim()
                            
                            # Save schema to file with UTF8 encoding without BOM
                            [System.IO.File]::WriteAllText($schemaFile, $xmlContent)
                            
                            $message = "Schema successfully saved to: $schemaFile"
                            Write-Host $message -ForegroundColor Green
                            $message | Out-File $logFile -Append
                        }
                        else {
                            $message = "Could not find manifest XML in output. This may indicate an issue with the Sysmon version or command."
                            Write-Warning $message
                            $message | Out-File $logFile -Append
                        }
                    }
                    catch {
                        $message = "Error during schema extraction from $($dir.Name): $($_.Exception.Message)"
                        Write-Warning $message
                        $message | Out-File $logFile -Append
                    }
                }
                else {
                    $message = "Schema extraction not supported for Sysmon version $version (requires v6.0 or higher)"
                    Write-Host $message -ForegroundColor Yellow
                    $message | Out-File $logFile -Append
                }
            }
            else {
                $message = "Schema file already exists: $schemaFile"
                Write-Host $message -ForegroundColor Yellow
                $message | Out-File $logFile -Append
            }
        }
        catch {
            $message = "Error processing $($dir.Name): $($_.Exception.Message)"
            Write-Warning $message
            $message | Out-File $logFile -Append
        }
    }
    else {
        $message = "Sysmon.exe not found in $($dir.Name)"
        Write-Warning $message
        $message | Out-File $logFile -Append
    }
}

# Write completion to log
"Finished processing at $(Get-Date)" | Out-File $logFile -Append