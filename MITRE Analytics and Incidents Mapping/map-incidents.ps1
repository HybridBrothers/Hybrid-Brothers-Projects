<#

    .DESCRIPTION
    This script maps Microsoft Sentinel incidents to the MITRE ATT&CK framework, setting the score of the techniques to the amount of 
	related incidents, and setting the incident IDs and links to the portal in the links field. Filters can be used to map only incidents within a 
	specific timeframe, with a certain status, and with a certain incident provider.

	This script can be run in an interactive and non-interactive mode. The interactive mode logs in with the user context, and the non-interactive mode
	uses the client-credential authentication flow. 

    #######################################
    ##### Global parameters #####
    #######################################
    .PARAMETER resourceGroupName [String]
    The name of the resource group where the Sentinel workspace resides.
    .PARAMETER workspaceName [String]
    The name of the Sentinel Log Analytics workspace.
	.PARAMETER attackVersion [String] <not mandatory>
	The version of the ATT&CK franework you want to use.
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
	.PARAMETER statusFilter [Array] <not mandatory>
    The filter you can use to filter the status of the incidents. This filter is an array where you can create all combinations based on 
	'New', 'Active', and 'Closed'. If you want all statuses , you can just add 'all' to the array. Default value is @('all').
	.PARAMETER providerFilter [Array] <not mandatory>
    The filter you can use to filter based on the provider. This filter is an array where you can create all combinations based on 
	"Azure Advanced Threat Protection", "Azure Security Center", "Azure Sentinel", "Microsoft 365 Defender", "Microsoft Cloud App Security", 
	"Microsoft Defender Advanced Threat Protection", "Office 365 Advanced Threat Protection", "Azure Defender for IoT". If you want all providers, 
	you can just add 'all' to the array. Default value is @('all').
	.PARAMETER lookback [String] <not mandatory>
    The lookback period for the incidents. Default value is 30.

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
	[Parameter (Mandatory=$false)]
	[ValidateSet ("13","14","latest")]
    [string] $attackVersion = "latest",

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
	[Parameter (ParameterSetName='noninteractive',Mandatory=$false)]
    [array] $statusFilter = @("all"),
	[Parameter (ParameterSetName='noninteractive',Mandatory=$false)]
    [array] $providerFilter = @("all"),
	[Parameter (ParameterSetName='noninteractive',Mandatory=$false)]
    [string] $lookback = "30",

	[Parameter (ParameterSetName='interactive',Mandatory=$false)]
	[switch] $interactive
)


###############################
# Because why not
###############################
Write-Host ""
@'                                                    

███╗   ███╗██╗████████╗██████╗ ███████╗    ██╗███╗   ██╗ ██████╗██╗██████╗ ███████╗███╗   ██╗████████╗███████╗
████╗ ████║██║╚══██╔══╝██╔══██╗██╔════╝    ██║████╗  ██║██╔════╝██║██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝
██╔████╔██║██║   ██║   ██████╔╝█████╗      ██║██╔██╗ ██║██║     ██║██║  ██║█████╗  ██╔██╗ ██║   ██║   ███████╗
██║╚██╔╝██║██║   ██║   ██╔══██╗██╔══╝      ██║██║╚██╗██║██║     ██║██║  ██║██╔══╝  ██║╚██╗██║   ██║   ╚════██║
██║ ╚═╝ ██║██║   ██║   ██║  ██║███████╗    ██║██║ ╚████║╚██████╗██║██████╔╝███████╗██║ ╚████║   ██║   ███████║
╚═╝     ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚═╝╚═╝  ╚═══╝ ╚═════╝╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝
                                                                                                              
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
# Function
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

function startConversions() {
	param (
		$numberOfDays,
		$authHeader, 
		$filter,
		$providerFilter,
		$filtername
	)

	###############################
	# API requests
	###############################
	# Calculate maximum time
	$createdTimeUTC = (Get-Date).AddDays(-$numberOfDays).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
	$datefilter = "properties/createdTimeUtc ge $createdTimeUTC"
	# URI from API
	$uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/incidents?`$filter=$datefilter&`$top=50&api-version=2023-02-01-preview"
	# Array for all the incidents
	$incidentList = @()
	# HTTP request
	$response = Invoke-RestMethod -Uri $uri -Method Get -Headers $authHeader -UseBasicParsing
	$incidentList += $response.value
	# Loop to retrieve all the incidents via the nexlink parameter (Invoke-RestMethod limiet at 50)
	while ($response.'nextLink') {
		# Extract the next link URI and parse out the skiptoken value
		$nextLinkUri = $response.'nextLink'
		$response = Invoke-RestMethod -Uri $nextLinkUri -Method Get -Headers $authHeader -UseBasicParsing
		# Add the incidents from the current response to the incident array
		$incidentList += $response.value
	}


	###############################
	# Data manipulation
	###############################
	# Convert JSON files
	$data = $incidentList | ConvertTo-Json -Depth 10 | ConvertFrom-Json
	# Array for all techniques
	$techniquesList = @()
	# Loop to get all techniques + add them to array
	foreach ($incident in $data) {
		# Save important properties
		$incidentStatus = $incident.properties.status
		$incidentProviders = $incident.properties.additionalData.alertProductNames
		# Return only the techniques from a certain status
		if(&$filter) {
			# Return only techniques if provider is in filter
			:providerLoop1 foreach ($provider in $providerFilter) {
				if ($incidentProviders -contains $provider) {
					$techniquesList += $incident.properties.additionalData.techniques
					$openIncidents++
					break providerLoop1
				}
			}
		}
	}


	###############################
	# Outputs
	###############################
	Write-Host "┏━━━" -ForegroundColor Cyan
	Write-Host "┃ Statistics" -ForegroundColor Cyan
	Write-Host "┗━━━" -ForegroundColor Cyan
	# Display total number of techniques retrieved
	Write-Output "  ┖─ Returned incidents of the last $($numberOfDays) days."
	# Display the total number of incidents retrieved
	Write-Output "  ┖─ Total number of incidents retrieved: $($incidentList.Count)"
	Write-Output "  ┖─ Total number of filtered incidents retrieved: $($openIncidents)"
	Write-Output "  ┖─ Total number of techniques retrieved: $($techniquesList.count)"
	# make a table with technique name and count + gives the occurrence of each technique
	$countAllTechniques = $techniquesList | Group-Object | Select-Object name, count
	# Display occurrence of each technique
	Write-Host "┏━━━" -ForegroundColor Cyan
	Write-Host "┃ Techniques matrix" -ForegroundColor Cyan
	Write-Host "┗━━━" -ForegroundColor Cyan
	$countAllTechniques | ForEach-Object { Write-Output "  ┖─ $($_.name) x $($_.count)"}
	# Returns maximum number of all the techniques => max value used for gradient in matrix
	$maxCount = $countAllTechniques | Measure-Object -Maximum count
	$maxNumber = $countAllTechniques | Where-Object {$_.count -eq $maxCount.Maximum} | Select-Object -First 1


	###############################
	# Data Manipulation
	###############################
	# Hashtable for the incidentNumbers and incidentsURLs of all the incidents
	$linkData = @{}
	# Loop to add incidentNumber and incidentURL to the hastable
	# Loop to get each incident
	foreach($incident in $data) {
		# Get the data from each incident
		$incidentNumber= $incident.properties.incidentNumber.ToString()
		$IncidentTechniques = $incident.properties.additionalData.techniques
		$incidentURL = $incident.properties.incidentURL
		$incidentStatus = $incident.properties.status
		$incidentProviders = $incident.properties.additionalData.alertProductNames
		# Return only the link data from a certain status
		if(&$filter) {
			# Return only techniques if provider is in filter
			:providerLoop2 foreach ($provider in $providerFilter) {
				if ($incidentProviders -contains $provider) {
					# Loop for each technique used in each incident
					# (needs to be here because sometimes multiple techniques per incident)
					foreach($technique in $IncidentTechniques) {
						# Create new object
						$obj = [PSCustomObject] @{
							label = $incidentNumber
							url = $incidentURL
						}
						# Check if technique already exist in hashtable
						if($linkData.ContainsKey($technique)) {
							# Add incident data (nr + url) to hashtable of corresponding technique
							$linkData[$technique] += $obj
						} else {
							# Add new technique to hashtable + corresponding incident data (nr + url)
							$linkData.Add($technique, @($obj))
						}
					}
					break providerLoop2
				}
			}
		}
	}



	###############################
	# Create layers
	###############################
	$filename = "incidents"
	# Check and create directory
	if (!(Test-Path -Path ".\layers")) {
		New-Item -ItemType Directory -Force -Path ".\layers"
	}
	# Define the output file
	$outputFile = ".\layers\$filename-$filtername.json"
	if (Test-Path -Path outputFile) {
		Remove-Item outputFile
	} else {
		New-Item outputFile -ItemType "file" | Out-Null
	}


	###############################
	# MITRE template
	###############################
	# Get MITRE ATT&CK Layer and set name and max value
	$layer = Get-Content ".\attack-layer-templates\layer-v$($attackVersion).json" | ConvertFrom-Json
	$layer.name = "$filename-$filtername"
	$layer.gradient.maxValue = "$($maxNumber.count)"
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
					"metadata" = @()
					"links" = $linkData[$incidentTechnique.name]
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
	# Filter menu
	###############################
	Write-Host "┏━━━" -ForegroundColor Cyan
	Write-Host "┃ Please select the status filter for the incidents" -ForegroundColor Cyan
	Write-Host "┗━━━" -ForegroundColor Cyan
	# Ask user to filter on which status
	$userNumber = Read-Host "  ┖─ 1: New `n  ┖─ 2: Active `n  ┖─ 3: Closed `n  ┖─ 4: New and Active `n  ┖─ 5: New and Closed `n  ┖─ 6: Active and Closed `n  ┖─ 7: All status `n─ Select filter"
	# Return filter to get the right status
	switch ($userNumber) {
		1 { $filter = {$incidentStatus -eq "New" }; $filtername = "New"; break }
		2 { $filter = {$incidentStatus -eq "Active" }; $filtername = "Active"; break }
		3 { $filter = {$incidentStatus -eq "Closed" }; $filtername = "Closed"; break }
		4 { $filter = {$incidentStatus -eq "New" -or $incidentStatus -eq "Active" }; $filtername = "NewActive"; break }
		5 { $filter = {$incidentStatus -eq "New" -or $incidentStatus -eq "Closed" }; $filtername = "NewClosed";  break }
		6 { $filter = {$incidentStatus -eq "Active" -or $incidentStatus -eq "Closed" }; $filtername = "ActiveClosed"; break }
		7 { $filter = {$incidentStatus -eq "New" -or $incidentStatus -eq "Active" -or $incidentStatus -eq "Closed"}; $filtername = "All"; break }
		Default { $filter = "Invalid number"; break }
	}
	Write-Host "┏━━━" -ForegroundColor Cyan
	Write-Host "┃ Please select the provider filter for the incidents" -ForegroundColor Cyan
	Write-Host "┗━━━" -ForegroundColor Cyan
	# Ask user to filter on provider
	$providerNumber = Read-Host "  ┖─ 1: MS Defender for Identity `n  ┖─ 2: Defender for Cloud `n  ┖─ 3: MS Sentinel `n  ┖─ 4: MS 365 Defender `n  ┖─ 5: MS Defender for Cloud Apps `n  ┖─ 6: MS Defender for Endpoint `n  ┖─ 7: MS Defender for Office 365 `n  ┖─ 8: MS Defender for IoT `n  ┖─ 9: All from Defender suite `n  ┖─ 10: All `n"
	# Return filter for provider
	switch ($providerNumber) {
		1 { $providerFilter = @("Azure Advanced Threat Protection"); break }
		2 { $providerFilter = @("Azure Security Center"); break }
		3 { $providerFilter = @("Azure Sentinel"); break }
		4 { $providerFilter = @("Microsoft 365 Defender"); break }
		5 { $providerFilter = @("Microsoft Cloud App Security"); break }
		6 { $providerFilter = @("Microsoft Defender Advanced Threat Protection"); break }
		7 { $providerFilter = @("Office 365 Advanced Threat Protection"); break }
		8 { $providerFilter = @("Azure Defender for IoT"); break }
		9 { $providerFilter = @("Azure Advanced Threat Protection", "Azure Security Center", "Microsoft 365 Defender", "Microsoft Cloud App Security", "Microsoft Defender Advanced Threat Protection", "Office 365 Advanced Threat Protection", "Azure Defender for IoT"); break }
		10 { $providerFilter = @("Azure Advanced Threat Protection", "Azure Security Center", "Azure Sentinel", "Microsoft 365 Defender", "Microsoft Cloud App Security", "Microsoft Defender Advanced Threat Protection", "Office 365 Advanced Threat Protection", "Azure Defender for IoT"); break }
	}
	$numberOfDays = Read-Host "─ How many days of incidents do you want to return?"

	startConversions -numberOfDays $numberOfDays -authHeader $authHeader -filter $filter -providerFilter $providerFilter -filtername $filtername
}


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

	###############################
	# Set status filter correct
	###############################
	if ($statusFilter.Contains("all")) {
		$filter = {$incidentStatus -eq "New" -or $incidentStatus -eq "Active" -or $incidentStatus -eq "Closed"}; $filtername = "All";
	} elseif ($statusFilter.Contains("New") -and $statusFilter.Contains("Active") -and $statusFilter.Contains("Closed")) {
		$filter = {$incidentStatus -eq "New" -or $incidentStatus -eq "Active" -or $incidentStatus -eq "Closed"}; $filtername = "All";
	} elseif ($statusFilter.Contains("New") -and $statusFilter.Contains("Active")) {
		$filter = {$incidentStatus -eq "New" -or $incidentStatus -eq "Active"}; $filtername = "NewActive";
	} elseif ($statusFilter.Contains("New") -and $statusFilter.Contains("Closed")) {
		$filter = {$incidentStatus -eq "New" -or $incidentStatus -eq "Closed"}; $filtername = "NewClosed";
	} elseif ($statusFilter.Contains("Active") -and $statusFilter.Contains("Closed")) {
		$filter = {$incidentStatus -eq "Active" -or $incidentStatus -eq "Closed"}; $filtername = "ActiveClosed";
	} elseif ($statusFilter.Contains("Active")) {
		$filter = {$incidentStatus -eq "Active"}; $filtername = "Active";
	} elseif ($statusFilter.Contains("New")) {
		$filter = {$incidentStatus -eq "New"}; $filtername = "New";
	} elseif ($statusFilter.Contains("Closed")) {
		$filter = {$incidentStatus -eq "Closed"}; $filtername = "Closed";
	}


	###############################
	# Set provider filter correct
	###############################
	if ($providerFilter.Contains("all")) {
		$providerFilter = @("Azure Advanced Threat Protection", "Azure Security Center", "Azure Sentinel", "Microsoft 365 Defender", "Microsoft Cloud App Security", "Microsoft Defender Advanced Threat Protection", "Office 365 Advanced Threat Protection", "Azure Defender for IoT")
	}

	# Start the conversions
	startConversions -numberOfDays $lookback -authHeader $authHeader -filter $filter -providerFilter $providerFilter -filtername $filtername
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