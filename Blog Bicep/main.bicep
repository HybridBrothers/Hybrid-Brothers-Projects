//--------------------
// Parameters
//--------------------
param location string = deployment().location
param application string
param vnetConfig object
param acaConfig object
param dbConfig object

@allowed(['prod', 'test'])
param environment string

//--------------------
// Targetscope
//--------------------
targetScope = 'subscription'

//--------------------
// Variables
//--------------------
var containerAppName = 'ca-${application}-${environment}-${location}-001'

//--------------------
// Basic infra
//--------------------
resource containerAppRG 'Microsoft.Resources/resourceGroups@2022-09-01' = {
  name: 'rg-${application}-${environment}-${location}-001'
  location: location
}

// Keyvault
resource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' existing = {
  name: 'e8bu9d4g29gxqzqm45g4'
  scope: resourceGroup('rg-secrets-prod-westeurope-001')
}

// Network Infra
module networkInfra 'networkInfra.bicep' = {
  name: 'deploy_network'
  scope: containerAppRG
  params: {
    location: location
    application: application
    environment: environment 
    vnetConfig: vnetConfig
  }
}

// Storage Infra
module storageInfra 'storageInfra.bicep' = {
  name: 'deploy_storage'
  scope: containerAppRG
  params: {
    location: location
    application: application
    environment: environment 
    acaConfig: acaConfig
  }
}

// Database Infra
module databaseInfra 'databaseInfra.bicep' = {
  name: 'deploy_database'
  scope: containerAppRG
  params: {
    location: location
    application: application
    environment: environment 
    containerAppName: containerAppName
    dbConfig: dbConfig
    dbPassword: keyVault.getSecret('MySQLPassword')
  }
}

// LogAnalytics Infra
module logAnalyticsInfra 'logAnalyticsInfra.bicep' = {
  name: 'deploy_loganalytics'
  scope: containerAppRG
  params: {
    location: location
    application: application
    environment: environment 
  }
}

// Backup Infra
module backupInfra 'backupInfra.bicep' = {
  name: 'deploy_backup'
  scope: containerAppRG
  params: {
    location: location
    application: application
    environment: environment 
    storageAccountName: storageInfra.outputs.storageAccountName
  }
}

// ContainerApp
module containerApp 'containerApp.bicep' = {
  name: 'deploy_containerapp'
  scope: containerAppRG
  params: {
    location: location
    application: application
    environment: environment 
    acaConfig: acaConfig
    dbConfig: dbConfig
    dbPassword: keyVault.getSecret('MySQLPassword')
    mailPassword: keyVault.getSecret('MailPassword')
    containerAppName: containerAppName
    logAnalyticsWorkspaceName:logAnalyticsInfra.outputs.logAnalyticsWorkspaceName
    storageAccountName: storageInfra.outputs.storageAccountName
    storageAccountKey: storageInfra.outputs.storageAccountKey
    websiteContentShareName: storageInfra.outputs.websiteContentShareName
  }
}
