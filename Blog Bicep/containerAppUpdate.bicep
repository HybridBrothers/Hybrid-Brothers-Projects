//--------------------
// Parameters
//--------------------
param location string
param environment string
param application string
param acaConfig object
param containerSecrets array
param containers array
param containerVolumes array

//--------------------
// Targetscope
//--------------------
targetScope = 'resourceGroup'

//--------------------
// Variables
//--------------------

//--------------------
// Container apps env
//--------------------

// Container Apps Environment
resource  containerAppsEnvironment 'Microsoft.App/managedEnvironments@2023-04-01-preview' existing = {
  name: 'cae-${application}-${environment}-${location}-001'
}

// Container App Env Certificate
resource containerAppsEnvCertificate 'Microsoft.App/managedEnvironments/managedCertificates@2023-04-01-preview' = {
  name: acaConfig.url
  parent: containerAppsEnvironment
  location: location
  properties: {
    domainControlValidation: 'HTTP'
    subjectName: acaConfig.url
  }
}

//--------------------
// Container app
//--------------------

// Container App
resource containerApp 'Microsoft.App/containerApps@2023-04-01-preview' = {
  name: 'ca-${application}-${environment}-${location}-001'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    managedEnvironmentId: containerAppsEnvironment.id
    configuration: {
      secrets: containerSecrets
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 2368
        transport: 'auto'
        customDomains:  [
          {
            certificateId: containerAppsEnvCertificate.id
            name: acaConfig.url
            bindingType: 'SniEnabled'
          }
        ]
        allowInsecure: false
      }
    }
    template: {
      containers: containers
      scale: {
        minReplicas: 1
        maxReplicas: 3
      }
      volumes: containerVolumes
    }
  }
}
