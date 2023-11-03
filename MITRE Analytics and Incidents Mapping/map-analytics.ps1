<#

    .DESCRIPTION
    This script maps Microsoft Sentinel Analytic rules to the MITRE ATT&CK framework, setting the score of the techniques to the amount of 
	related analytic rules, and setting the names of the analytic rules in the metadata field. Filters can be used to map active analytic rules or 
	template analytic rules, and only map analytic rules to a specific data connector.

	This script can be run in an interactive and non-interactive mode. The interactive mode logs in with the user context, and the non-interactive mode
	uses the client-credential authentication flow. 

    #######################################
    ##### Global parameters #####
    #######################################
    .PARAMETER resourceGroupName [String]
    The name of the resource group where the Sentinel workspace resides.
    .PARAMETER workspaceName [String]
    The name of the Sentinel Log Analytics workspace.
    .PARAMETER interactive or `noninteractive` [Switch] <not mandatory>
    The flags used to run in interactive or noninteractive mode

    #######################################
    ### Parameters for interactive mode ###
    #######################################
    No extra parameters needed

    #######################################
    #### Parameters for non-interactive mode ####
    #######################################
    .PARAMETER subscriptionId [String]
    The id of the subscription where the Sentinel workspace lives.
    .PARAMETER appId [String]
    The application id of the App Registration you are using to login.
    .PARAMETER secret [String]
    The client secret configured on the App Registration to login.
	.PARAMETER tenantId [String]
    The tenant id of the tenant you are logging into.
	.PARAMETER alertRuleType [String]
    The type of analytic rules you want to map. Possible values are 'alertRules' or 'alertRuleTemplates'.
	.PARAMETER dataConnectorFilter [String] <not mandatory>
    The filter of relevant data connectors. Possible values can be found in lookuptable/data_sources.json. Default value is set to 'all', meaning no data connector filter.

#>
###############################
# Parameters
###############################
[CmdletBinding()]
param (
    [Parameter (Mandatory=$true)]
    [string] $resourceGroupName,
    [Parameter (Mandatory=$true)]
    [string] $workspaceName,
	[Parameter (Mandatory=$true)]
	[ValidateSet ("13","14","latest")]
    [string] $attackVersion,

	[Parameter (ParameterSetName='noninteractive',Mandatory=$false)]
	[switch] $noninteractive,
	[Parameter (ParameterSetName='noninteractive',Mandatory=$true)]
    [string] $subscriptionId,
	[Parameter (ParameterSetName='noninteractive',Mandatory=$true)]
    [string] $appId,
	[Parameter (ParameterSetName='noninteractive',Mandatory=$true)]
    [string] $secret,
	[Parameter (ParameterSetName='noninteractive',Mandatory=$true)]
    [string] $tenantId,
	[Parameter (ParameterSetName='noninteractive',Mandatory=$true)]
    [string] $alertRuleType,
	[Parameter (ParameterSetName='noninteractive',Mandatory=$false)]
    [string] $dataConnectorFilter = "all",

	[Parameter (ParameterSetName='interactive',Mandatory=$false)]
	[switch] $interactive
)



###############################
# Because why not
###############################
Write-Host ""
@'

███╗   ███╗██╗████████╗██████╗ ███████╗     █████╗ ███╗   ██╗ █████╗ ██╗     ██╗   ██╗████████╗██╗ ██████╗███████╗
████╗ ████║██║╚══██╔══╝██╔══██╗██╔════╝    ██╔══██╗████╗  ██║██╔══██╗██║     ╚██╗ ██╔╝╚══██╔══╝██║██╔════╝██╔════╝
██╔████╔██║██║   ██║   ██████╔╝█████╗      ███████║██╔██╗ ██║███████║██║      ╚████╔╝    ██║   ██║██║     ███████╗
██║╚██╔╝██║██║   ██║   ██╔══██╗██╔══╝      ██╔══██║██║╚██╗██║██╔══██║██║       ╚██╔╝     ██║   ██║██║     ╚════██║
██║ ╚═╝ ██║██║   ██║   ██║  ██║███████╗    ██║  ██║██║ ╚████║██║  ██║███████╗   ██║      ██║   ██║╚██████╗███████║
╚═╝     ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝   ╚═╝      ╚═╝   ╚═╝ ╚═════╝╚══════╝
                                                                                                                  
███╗   ███╗ █████╗ ██████╗ ██████╗ ██╗███╗   ██╗ ██████╗                                                          
████╗ ████║██╔══██╗██╔══██╗██╔══██╗██║████╗  ██║██╔════╝                                                          
██╔████╔██║███████║██████╔╝██████╔╝██║██╔██╗ ██║██║  ███╗                                                         
██║╚██╔╝██║██╔══██║██╔═══╝ ██╔═══╝ ██║██║╚██╗██║██║   ██║                                                         
██║ ╚═╝ ██║██║  ██║██║     ██║     ██║██║ ╚████║╚██████╔╝                                                         
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝                                                          
      
By Robbe Van den Daele @ HybridBrothers

'@ | Write-Host -ForegroundColor Cyan
Start-Sleep -Seconds 3


###############################
# Functions
###############################
function installModules {
	param ()

	# --------------------
	# Check for required modules
	# --------------------
	# Set required module
	$modulesToInstall = @(
		'Az.Accounts'
	)
	# Install and importing modules
	Write-Host "┏━━━" -ForegroundColor Cyan
	Write-Host "┃  Installing/Importing PowerShell modules" -ForegroundColor Cyan
	Write-Host "┗━━━" -ForegroundColor Cyan
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
	
}

function createDisplayNameTechniquesList {
	param (
		$list
	)
	
	# loop to add all the analytics display names to the related techniques
	foreach($technique in $list) {
		# Check if technique already exist in hashtable
		if($displayNameList.ContainsKey($technique)) {
			# Add display name to hashtable of corresponding technique
			$addName = "`n$displayName`n"
			$displayNameList[$technique] += $addName
		} else {
			# Add new technique to hashtable + corresponding analytic name
			$displayNameList.Add($technique, "$displayName`n")
		}
	}
}


function sendRequest {
	param (
		$uri,
		$headers
	)
	$list = @()
	# HTTP request
	$response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -UseBasicParsing
	$list += $response.value
	# Loop to retrieve all the incidents via the nexlink parameter (Invoke-RestMethod limiet at 50)
	while ($response.'nextLink') {
		# Extract the next link URI and parse out the skiptoken value
		$nextLinkUri = $response.'nextLink'
		$response = Invoke-RestMethod -Uri $nextLinkUri -Method Get -Headers $authHeader -UseBasicParsing
		# Add the rules from the current response to the rules array
		$list += $response.value
	}
	return $list
}

function getAuthHeader() {
	param()

	# Get Access token from Az-Context
	$context = Get-AzContext
	$azureProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
	$profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azureProfile)
	$token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
	# Set header
	return @{
		'Content-Type'  = 'application/json'
		'Authorization' = 'Bearer ' + $token.AccessToken
	}
}

function startConversions() {
	param(
		$providedFilter,
		$analyticURL,
		$authHeader
	)

	# Check user input, and set filter and filtername
	if($providedFilter -eq "all") {
		$filter = {"true"}
		$filtername = "all"
	} else {
		$filter = {$dataSource -eq $providedFilter }
		$filtername = $providedFilter
	}
	# Check which rules need to be returned
	if ($analyticURL -eq "alertRuleTemplates") {
		# Set filename
		$filename = "alertRuleTemplates"
		Write-Host "✓ Returning $filtername alert rule templates" -ForegroundColor Green

	} else {
		# Set filename
		$filename = "activeRules"
		Write-Host "✓ Returning $filtername active alert rules" -ForegroundColor Green
	}


	###############################
	# API requests
	###############################
	# URI from API
	$uriActives= "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-02-01&$top=50"
	$uriTemplates = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRuleTemplates?api-version=2023-02-01&$top=50"
	# Define arrays and objects
	$analyticRules = @()
	$analyticRuleTemplates = @()
	$data = @{}
	# Save relevant rules
	# ALways get templates (either for templates or correlations with active rules)
	$analyticRuleTemplates = sendRequest -uri $uriTemplates -headers $authHeader
	if ($analyticURL -eq "alertRules") { 
		# Save rules
		$analyticRules = sendRequest -uri $uriActives -headers $authHeader
		# Add required data connectors field from related template to active rules object
		$analyticRules | ForEach-Object {
			$templateName = $_.Properties.alertRuleTemplateName
			$relatedObj = $analyticRuleTemplates | Where-Object { $_.name -eq $templateName }
			$_.Properties | Add-Member -MemberType NoteProperty -Name "requiredDataConnectors" -Value $relatedObj.Properties.requiredDataConnectors
		}
		$data = $analyticRules | ConvertTo-Json -Depth 10 | ConvertFrom-Json
	} else {
		$data = $analyticRuleTemplates | ConvertTo-Json -Depth 10 | ConvertFrom-Json
	}


	###############################
	# Data manipulation
	###############################
	# Array for all techniques
	$techniquesList = @()
	$displayNameList = @{}
	$countAnalytics = 0
	# Loop to get all techniques + add them to array
	foreach ($analytic in $data) {
		# Save important properties
		$displayName = $analytic.properties.displayName
		# Save data source
		$dataSource = $analytic.properties.requiredDataConnectors.connectorId
		# Apply filter set in menu. When 'all' was choosen, the filter will return alwas true. When a data connector was choosen, the filter will
		# evaluate $dataSource -eq $userSource
		if(&$filter) {
			$techniquesList += $analytic.properties.techniques
			$countAnalytics++
			createDisplayNameTechniquesList($analytic.properties.techniques)
		}
	}
	Write-Host "┏━━━" -ForegroundColor Cyan
	Write-Host "┃ Statistics" -ForegroundColor Cyan
	Write-Host "┗━━━" -ForegroundColor Cyan
	# Display the total number of rules retrieved
	Write-Host "  ┖─ Total number of analytic rules retrieved: $($data.Count)"
	# Display total number of techniques retrieved
	Write-Host "  ┖─ Total number of filtered analytics retrieved: $countAnalytics"
	Write-Host "  ┖─ Total number of techniques retrieved: $($techniquesList.count)"
	# make a table with technique name and count + gives the occurrence of each technique
	$countAllTechniques = $techniquesList | Group-Object | Select-Object name, count
	# Display occurrence of each technique
	Write-Host "┏━━━" -ForegroundColor Cyan
	Write-Host "┃ Techniques matrix" -ForegroundColor Cyan
	Write-Host "┗━━━" -ForegroundColor Cyan
	$countAllTechniques | ForEach-Object { Write-Host "  ┖─ $($_.name) x $($_.count)"}
	# Returns maximum number of all the techniques => max value used for gradient in matrix
	$maxCount = $countAllTechniques | Measure-Object -Maximum count
	$maxNumber = $countAllTechniques | Where-Object {$_.count -eq $maxCount.Maximum} | Select-Object -First 1


	###############################
	# Create layers
	###############################
	# Check and create directory
	if (!(Test-Path -Path ".\layers")) {
		New-Item -ItemType Directory -Force -Path ".\layers"
	}
	# Define the output file
	$outputFile = ".\layers\$filename-$filtername.json"
	# Create layer file
	if (Test-Path -Path $outputFile) {
		Remove-Item $outputFile
	} else {
		New-Item $outputFile -ItemType "file" | Out-Null
	}


	###############################
	# MITRE template
	###############################
	# Get MITRE ATT&CK Layer and set name and max value
	$layer = Get-Content ".\attack-layer-templates\layer-v$($attackVersion).json" | ConvertFrom-Json
	$layer.name = "$filename-$filtername"
	$layer.gradient.maxValue = "$($maxNumber.count)"
	# Get content from the lookup table to get tactic name
	$LookUpMatrixMitreAttack =  Get-Content ".\lookuptable\matrix-v$($attackVersion).json" -Raw | ConvertFrom-Json
	# Loop to get each technique from the incidents
	foreach($incidentTechnique in $countAllTechniques) {
		#Loop through each technique in the matrix lookup table
		foreach ($Matrixtechnique in $LookUpMatrixMitreAttack.techniques) {
			# Check for the same incident technique in the matrix lookup table
			if ($Matrixtechnique.techniqueID -eq "$($incidentTechnique.name)") {
				# Make a JSON object for a new technique
				$newTechnique = @{
					"techniqueID" = $incidentTechnique.name
					"tactic" = $Matrixtechnique.tactic
					"score" = $incidentTechnique.count
					"color" = ""
					"comment" = ""
					"enabled" = $true
					"metadata" = @(
						@{
							"name" = "Related alert rules"
							"value" = $displayNameList[$incidentTechnique.name]
						}
					)
					"links" = @()
					"showSubtechniques" = $false
				}
				# Add the new technique to the MITRE ATT&CK layer
				$layer.techniques += $newTechnique
			}
		}
	}
	# Export layer
	$layer | ConvertTo-Json -Depth 10 | Set-Content $outputFile
	Write-Host "`n✓ Layer file saved to $outputFile" -ForegroundColor Green
}

###############################
# Noninteractive mode
###############################
function noninteractiveMode() {
	param ()

	###############################
	# Access token and headers
	###############################
	$secureSecret = ConvertTo-SecureString -String $secret -AsPlainText -Force
	$pscredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $appId, $secureSecret
	# Login with client credential flow
	Connect-AzAccount -ServicePrincipal -Credential $pscredential -Tenant $tenantId | Out-Null
	$authHeader = getAuthHeader

	# Start the conversions
	startConversions -providedFilter $dataConnectorFilter -analyticURL $alertRuleType -authHeader $authHeader
}

###############################
# Interactive mode
###############################
function interactiveMode() {
	param ()


	###############################
	# Access token and headers
	###############################
	Write-Host "┏━━━" -ForegroundColor Cyan
	Write-Host "┃ Logging you in" -ForegroundColor Cyan
	Write-Host "┗━━━" -ForegroundColor Cyan
	Connect-AzAccount | Out-Null
	$authHeader = getAuthHeader

	###############################
	# Subscription selection
	###############################
	# Display subscription options
	Write-Host "┏━━━" -ForegroundColor Cyan
	Write-Host "┃ Please select the relevant subscription" -ForegroundColor Cyan
	Write-Host "┗━━━" -ForegroundColor Cyan
	$subscriptions = Get-AzSubscription
	for ($i=0; $i -lt $subscriptions.Count; $i++) {
		Write-Host "  ┖─ $($i+1): $($subscriptions[$i].Name)"
	}
	# Prompt user for selection
	$selectedSubscriptionIndex = Read-Host "─ Enter the number of the desired subscription"
	# Set selected subscription
	$selectedSubscription = $subscriptions[$selectedSubscriptionIndex - 1]
	$subscriptionId = $selectedSubscription.SubscriptionId
	# Set Az-Context
	Set-AzContext -SubscriptionId $subscriptionId | Out-Null
	Write-Host "`n✓ Selected subscription: $($selectedSubscription.Name)`n" -ForegroundColor Green


	###############################
	# Active rules or templates menu
	###############################
	# Filter for alertRules or alertRuleTemplates
	Write-Host "┏━━━" -ForegroundColor Cyan
	Write-Host "┃ Please select which type of analytic rules needs to be retrieved" -ForegroundColor Cyan
	Write-Host "┗━━━" -ForegroundColor Cyan
	Write-Host "  ┖─ alertRuleTemplates (for template alert rules)"
	Write-Host "  ┖─ alertRules (for active alert rules)"
	$alertRuleType = Read-Host "─ Rule type: "
	# Data connector filter
	Write-Host "┏━━━" -ForegroundColor Cyan
	Write-Host "┃ Data connector filter" -ForegroundColor Cyan
	Write-Host "┗━━━" -ForegroundColor Cyan
	# Get available data sources
	Get-Content .\lookuptable\data_sources.json | ConvertFrom-Json | Format-Table -AutoSize | Out-Host
	# User input
	$dataConnectorFilter = Read-Host "`n  ┖─ Use datasource from list above to create mapping for one datasource `n  ┖─ Use 'all' to create mapping for all available templates `n─ Choose filter: "
	
	# Start the conversions
	startConversions -providedFilter $dataConnectorFilter -analyticURL $alertRuleType -authHeader $authHeader
}


###############################
# Main
###############################
# Install required modules
installModules
# Check version
if ($attackVersion -eq "latest") {
	[System.Collections.ArrayList]$validValues = (Get-Variable "attackVersion").Attributes.ValidValues
	$validValues.Remove("latest")
	$attackVersion = $(($validValues | Measure-Object -Maximum).Maximum)
}
# Start tool in certain mode
if ($interactive) {
	interactiveMode
} else {
	noninteractiveMode
}
