//--------------------
// Parameters
//--------------------
param location string
param environment string
param application string
//--------------------
// Targetscope
//--------------------
targetScope = 'resourceGroup'

//--------------------
// Variables
//--------------------

//--------------------
// Log Analytics
//--------------------

// Log Analytics Workspace
resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'log-${application}-${environment}-${location}-001'
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}
output logAnalyticsWorkspaceName string = logAnalyticsWorkspace.name
