//--------------------
// Parameters
//--------------------
param location string
param environment string
param application string
param acaConfig object
param dbConfig object
@secure()
param dbPassword string
@secure()
param mailPassword string
param logAnalyticsWorkspaceName string
@secure()
param storageAccountKey string
param storageAccountName string
param websiteContentShareName string
param subnetId string = ''
param containerAppName string

//--------------------
// Targetscope
//--------------------
targetScope = 'resourceGroup'

//--------------------
// Variables
//--------------------
var containers = [
  {
    image: 'docker.io/ghost:latest'
    name: '${environment}-${location}-ca-website'
    env: containerVars
    resources: {
      cpu: 1
      memory: '2Gi'
    }
    probes:containerProbes
    volumeMounts: [
      {
        volumeName: 'contentmount'
        mountPath: '/var/lib/ghost/content'
      }
    ]
  }
]
var containerVolumes = [
  {
    name: 'contentmount'
    storageType: 'AzureFile'
    storageName: 'contentmount'
  }
]
var containerProbes = [
  {
    type: 'Liveness'
    failureThreshold: 3
    httpGet: {
      path: '/ghost/#/signin'
      port: 2368
      scheme: 'HTTP'
    }
    initialDelaySeconds: 5
    periodSeconds: 15
    successThreshold: 1
    timeoutSeconds: 1
  }
  {
    type: 'Readiness'
    failureThreshold: 3
    initialDelaySeconds: 5
    periodSeconds: 10
    successThreshold: 1
    tcpSocket: {
      port: 2368
    }
    timeoutSeconds: 5
  }
]
var containerSecrets = [
  {
    name: 'database-connection-password'
    value: dbPassword
  }
  {
    name: 'mail-connection-password'
    value: mailPassword
  }
]
var containerVars = [
  {
    name: 'database__client'
    value: 'mysql'
  }
  {
    name: 'database__connection__host'
    value: '${dbConfig.serverName}.mysql.database.azure.com'
  }
  {
    name: 'database__connection__user'
    value: dbConfig.username
  }
  {
    name: 'database__connection__password'
    secretRef: 'database-connection-password'
  }
  {
    name: 'database__connection__database'
    value: dbConfig.dbname
  }
  {
    name: 'database__connection__port'
    value: '3306'
  }
  {
    name: 'url'
    value: 'https://${acaConfig.url}/'
  }
  {
    name: 'mail__transport'
    value: 'SMTP'
  }
  {
    name: 'mail__options__service'
    value: 'Mailgun'
  }
  {
    name: 'mail__options__host'
    value: 'smtp.eu.mailgun.org'
  }
  {
    name: 'mail__options__port'
    value: '465'
  }
  {
    name: 'mail__options__secureConnection'
    value: 'true'
  }
  {
    name: 'mail__options__auth__user'
    value: acaConfig.smtpUserName
  }
  {
    name: 'mail__options__auth__pass'
    secretRef: 'mail-connection-password'
  }
  {
    name: 'NODE_ENV'
    value: 'production'
  }
  {
    name: 'mail__from'
    value: 'info@hybridbrothers.com'
  }
]

//--------------------
// Container apps env
//--------------------

// Container Apps Environment
resource containerAppsEnvironment 'Microsoft.App/managedEnvironments@2023-04-01-preview' = {
  name: 'cae-${application}-${environment}-${location}-001'
  location: location
  properties: {
    infrastructureResourceGroup: 'rg-aca-${environment}-${location}-001'
    vnetConfiguration:{
      internal: false
      infrastructureSubnetId: subnetId
    }
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalyticsWorkspace.properties.customerId
        sharedKey: logAnalyticsWorkspace.listKeys().primarySharedKey
      }
    }
  }
}

// Container App Env Storagemount for content
resource containerAppsEnvStorageMountContent 'Microsoft.App/managedEnvironments/storages@2023-04-01-preview' = {
  name: 'contentmount'
  parent: containerAppsEnvironment
  properties: {
    azureFile: {
      accountName: storageAccountName
      shareName: websiteContentShareName
      accessMode: 'ReadWrite'
      accountKey: storageAccountKey
    }
  }
}

//--------------------
// Container app
//--------------------

// Reference existing loganalyics workspace
resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: logAnalyticsWorkspaceName
}

// Container App
resource containerApp 'Microsoft.App/containerApps@2023-04-01-preview' = {
  name: containerAppName
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
        customDomains: [
          {
            name: acaConfig.url
            bindingType: 'Disabled'
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

// Container App update for managed certificate
module containerAppUpdate 'containerAppUpdate.bicep' = {
  name: 'update_containerapp'
  params: {
    location: location
    application: application
    environment: environment
    acaConfig: acaConfig
    containers: containers
    containerSecrets: containerSecrets
    containerVolumes: containerVolumes
  }
  dependsOn:[
    containerApp
  ]
}

