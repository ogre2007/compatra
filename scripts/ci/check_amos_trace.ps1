param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$TracePath
)

if (-not (Test-Path $TracePath)) {
    Write-Error "Trace file not found: $TracePath"
    exit 1
}

$events = New-Object System.Collections.Generic.List[object]
Get-Content $TracePath | ForEach-Object {
    $line = $_.Trim()
    if (-not $line.StartsWith("{")) {
        return
    }
    try {
        $events.Add(($line | ConvertFrom-Json))
    } catch {
    }
}

function Require($Condition, [string]$Message) {
    if (-not $Condition) {
        Write-Error "AMOS trace check failed: $Message"
        exit 1
    }
}

function Has-Event {
    param(
        [string]$Plugin,
        [string]$Call,
        [string]$PathContains
    )

    foreach ($event in $events) {
        if ($Plugin -and $event.plugin -ne $Plugin) {
            continue
        }
        if ($Call -and $event.Call -ne $Call) {
            continue
        }
        if ($PathContains -and (-not ([string]$event.Path).Contains($PathContains))) {
            continue
        }
        return $true
    }
    return $false
}

Require ($events.Count -gt 0) "no JSONL events were parsed from emulator output"
Require (Has-Event -Plugin "detect" -Call "_main.GrabWallets") "AMOS did not reach _main.GrabWallets"
Require (Has-Event -Plugin "detect" -Call "_main.GrabChrome") "AMOS did not reach _main.GrabChrome"
Require (Has-Event -Plugin "detect" -Call "_main.GrabFirefox") "AMOS did not reach _main.GrabFirefox"
Require (
    Has-Event -Plugin "filemon" -Call "open" -PathContains "/Users/analyst/Library/Application Support/Binance/app-store.json"
) "AMOS did not attempt to open Binance wallet data"
Require (
    Has-Event -Plugin "filemon" -Call "read"
) "AMOS did not perform any file reads"
Require (
    Has-Event -Plugin "filemon" -Call "open" -PathContains "/Users/analyst/Library/Application Support/Firefox/Profiles/"
) "AMOS did not attempt to open Firefox profile data"
Require (
    Has-Event -Plugin "filemon" -Call "open" -PathContains "/Users/analyst/.electrum/wallets/"
) "AMOS did not attempt to open Electrum wallet data"

Write-Output "AMOS trace check passed"
