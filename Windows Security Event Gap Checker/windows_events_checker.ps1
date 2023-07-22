<#

    .DESCRIPTION
    This script checks which Windows Security Event IDs are being used in Sentinel analytic rules, and if they are being ingested in Microsoft Sentinel. The check on 
    whether the Event IDs are ingested is done by querying the SecurityEvents table for the past X days. This can help identify data mapping gaps that are otherwise
    hard to spot.

    This scipt can run into two modes, which are the 'autoCheck' and 'armTemplate' mode. The 'autoCheck' mode will get all the analytic rules from a workspace, 
    and check the used Event IDs for these. The 'armTemplate' mode expects a directory with exported ARM Templates of the analytic rules, and uses these to check 
    the used Event IDs.

    #######################################
    ##### Global parameters #####
    #######################################
    .PARAMETER subscriptionId [String]
    The subscription id of the Sentinel workspace that will be checked for current ingested Event IDs.
    .PARAMETER workspaceId [String]
    The workspace id of the Sentinel workspace that will be checked for current ingested Event IDs.
    .PARAMETER timespan [Int] <not mandatory>
    The lookup period in days of previously ingested Event IDs. Default is 7 days.

    #######################################
    ### Parameters for ArmTemplate mode ###
    #######################################
    .PARAMETER useArmTemplates [Switch]
    Flag that needs to be set when you want to use 'armTemplate' mode.
    .PARAMETER analyticsArmFolder [String]
    Folder that contains ARM Templates of analytic rules that needs to be checked

    #######################################
    #### Parameters for autoCheck mode ####
    #######################################
    .PARAMETER useAutoCheck [Switch]
    Flag that needs to be set when you want to use 'autoCheck' mode.
    .PARAMETER resourceGroupName [String]
    The resource group name of the Sentinel workspace that contains the analytic rules that needs to be checked.
    .PARAMETER workspaceName [String]
    The workspace name of the Sentinel workspace that contains the analytic rules that needs to be checked.

#>


# --------------------
# Get parameters
# --------------------
[CmdletBinding()]
param (
    [Parameter (Mandatory=$true)]
    [string] $subscriptionId = "",
    [Parameter (Mandatory=$true)]
    [string] $workspaceId = "",
    [Parameter (Mandatory=$false)]
    [int] $timespan = 7,

    [Parameter (ParameterSetName='arm',Mandatory=$false)]
    [switch] $useArmTemplates,
    [Parameter (ParameterSetName='arm',Mandatory = $true)]
    [String] $analyticsArmFolder = "",

    [Parameter (ParameterSetName='auto',Mandatory=$false)]
    [switch] $useAutoCheck,
    [Parameter (ParameterSetName='auto',Mandatory = $true)]
    [string] $resourceGroupName = "",
    [Parameter (ParameterSetName='auto',Mandatory = $true)]
    [string] $workspaceName = ""
)


# --------------------
# Functions
# --------------------
function Check-Events {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $displayName,

        [Parameter(Mandatory = $true)]
        [string] $query
    )

    # Set variables
    $usedEvents = @()
    # Check rule only if rule queries SecurityEvent table
    if ($query.Contains("SecurityEvent") -and $query.Contains("EventID")) {
        # Regex matching
        $match = Select-String 'EventID==(\d{3,4})|EventID == (\d{3,4})|EventID=="(\d{3,4})"|EventID == "(\d{3,4})"|EventID==''(\d{3,4})''|EventID == ''(\d{3,4})''|"((?:\d{3,4})+)",?|''((?:\d{3,4})+)'',?|\((\d{3,4}),?|[,\s]((?:\d{3,4})+)[,\s]|((?:\d{3,4})+)(?=\))' -InputObject $query -AllMatches
        # Since we are using multiple groups, we have to check which group got a successfull match (Groups will have index 0, 1, and 2)
        $match.Matches.Groups | ForEach-Object {
            if ($_.Success -eq $true -and $_.Name -ne 0) { $usedEvents += $_.Value } # Add success matches that are not in the first index to array
        }
        # Convert array to unique array
        $usedEvents = $usedEvents | Select-Object -Unique

        # Check if used events in analytic rule are being ingested in Sentinel
        Write-Host "┏━━━" -ForegroundColor Yellow
        Write-Host "┃ For rule with name '$displayName' the following events were found:" -ForegroundColor Yellow
        Write-Host "┗━━━" -ForegroundColor Yellow
        $usedEvents | ForEach-Object {
            if ($_ -in $ingestedEventIds) {
                Write-Host "    ✓ Found event $_ in analytic rule --> Event is being ingested in SecurityEvent table" -ForegroundColor Green 
            } else {
                Write-Host "    ✘ Found event $_ in analytic rule --> Event is is not being ingested in SecurityEvent table" -ForegroundColor Red
            }
        }
    }
    return $usedEvents
}


# --------------------
# KQL queries to run
# --------------------
$windowsEventsQuery = @"
    SecurityEvent
    | distinct EventID
"@


# --------------------
# Check for required modules
# --------------------
# Set required module
$modulesToInstall = @(
    'Az.Accounts',
    'Az.OperationalInsights',
    'Az.MonitoringSolutions'
)
# Install and importing modules
Write-Host "┏━━━" -ForegroundColor Yellow
Write-Host "┃  Installing/Importing PowerShell modules" -ForegroundColor Yellow
Write-Host "┗━━━" -ForegroundColor Yellow
# Install modules when they not exist
$modulesToInstall | ForEach-Object {
    if (-not (Get-Module -ListAvailable -All $_)) {
        Write-Host "Module [$_] not found, installing..." -ForegroundColor DarkGray
        Install-Module $_ -Force
    }
}
# Import modules
$modulesToInstall | ForEach-Object {
    Write-Host "Importing Module [$_]" -ForegroundColor DarkGray
    Import-Module $_ -Force
}


# --------------------
# Login and set correct subscription
# --------------------
# Set context
Write-Host "┏━━━" -ForegroundColor Yellow
Write-Host "┃  Logging you in..." -ForegroundColor Yellow
Write-Host "┗━━━" -ForegroundColor Yellow
Connect-AzAccount | Out-Null
Select-AzSubscription -subscriptionId $subscriptionId | Out-Null


# --------------------
# Get ingested Windows events
# --------------------
$queryResults = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceId -Query $windowsEventsQuery -Timespan (New-TimeSpan -Days $timespan) | Select-Object Results
$ingestedEventIds = $queryResults.Results | Select-Object -ExpandProperty "EventID"


# --------------------
# Read all analytic rules in analyticsArmFolder path
# --------------------
$events = @()
if ($useArmTemplates -eq $true) {
    Get-ChildItem $analyticsArmFolder -Filter *.json |
    # Loop through all files in directory
    ForEach-Object {
        # Get ARM JSON file of analytic rules
        $json = Get-Content $_.FullName | Out-String | ConvertFrom-Json
        # Loop through each analytic rule in file
        $json.resources | ForEach-Object {
            if ($_.kind -eq "Scheduled") {
                $event = Check-Events -displayName $_.properties.displayName -query $_.properties.query
                $events += $event
            }
        }
    }
}


# --------------------
# Read all analytic rules in workspace
# --------------------
if ($useAutoCheck -eq $true) {
    $rules = Get-AzSentinelAlertRule -ResourceGroupName $resourceGroupName -WorkspaceName $workspaceName | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    # Check if used events in analytic rule are being ingested in Sentinel
    $rules | ForEach-Object {
        if ($_.Query) {
            $event = Check-Events -displayName $_.DisplayName -query $_.Query
            $events += $event
        }
    }
}


# --------------------
# Write output of all used events
# --------------------
Write-Host "┏━━━" -ForegroundColor Yellow
Write-Host "┃ Used Events in all detected rules:" -ForegroundColor Yellow
Write-Host "┗━━━" -ForegroundColor Yellow
$events | Select-Object -Unique | ForEach-Object {
    Write-Host " ┖─ $_"
}


# --------------------
# Create XPath query
# --------------------
$XPath = "Security!*[System["
$events = $events | Select-Object -Unique
for ($i = 0; $i -lt $events.Count; $i++) {
    if ($i -lt $($events.Count - 1)) {
        $XPath += "(EventID=$($events[$i])) or "
    } else {
        $XPath += "(EventID=$($events[$i]))"
    }
}
$XPath += "]]"
Write-Host "┏━━━" -ForegroundColor Yellow
Write-Host "┃ XPath query to ingest used events in detection rules:" -ForegroundColor Yellow
Write-Host "┗━━━" -ForegroundColor Yellow
Write-Host " ┖─ $XPath"