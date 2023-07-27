//--------------------
// Parameters
//--------------------
param location string
param environment string
param application string
param dbConfig object
@secure()
param dbPassword string
param containerAppName string
param virtualNetworkId string = ''
param subnetId string = ''

//--------------------
// Targetscope
//--------------------
targetScope = 'resourceGroup'

//--------------------
// Variables
//--------------------
var mysqlURL = 'privatelink.mysql.database.azure.com'

//--------------------
// Database infra
//--------------------

// MySQL flexible server 
resource mySQLServer 'Microsoft.DBforMySQL/flexibleServers@2022-09-30-preview' = {
  name: dbConfig.serverName
  tags:{
    'hidden-title': 'mysql-${application}-${environment}-${location}-001'
  }
  location: location
  sku: {
    name: 'Standard_B1ms'
    tier: 'Burstable'
  }
  properties:{
    administratorLogin: dbConfig.username
    administratorLoginPassword: dbPassword
    storage: {
      storageSizeGB: 20
      iops: 360
      autoGrow: 'Enabled'
    }
    backup: {
      backupRetentionDays: 7
    }
    network:{
      publicNetworkAccess: 'Enabled'
    }
    version: '5.7'
  }
}

// MySQL Database
resource mySQLDatabase 'Microsoft.DBforMySQL/flexibleServers/databases@2022-01-01' =  {
  name: dbConfig.dbname
  parent: mySQLServer
}

// MySQL disable TLS
resource mySQLSSLConfig 'Microsoft.DBforMySQL/flexibleServers/configurations@2022-01-01' = {
  name: 'require_secure_transport'
  parent: mySQLServer
  properties:{
    value: 'OFF'
    source: 'user-override'
  }
}

// Reference existing containerapp
resource containerApp 'Microsoft.App/containerApps@2023-04-01-preview' existing = {
  name: containerAppName
}

// MySQL add firewall rule
resource mySQLFirewallRule 'Microsoft.DBforMySQL/flexibleServers/firewallRules@2022-01-01' = {
  name: 'allow-aca-outbound-ip'
  parent: mySQLServer
  properties:{
    startIpAddress: containerApp.properties.outboundIpAddresses[0]
    endIpAddress: containerApp.properties.outboundIpAddresses[0]
  }
}

// // MySQL private endpoint
resource privateMySQLEndpoint 'Microsoft.Network/privateEndpoints@2022-09-01' = {
  name: 'pep-${application}mysql-${environment}-${location}-001'
  location: location
  properties:{
    subnet: {
      id: subnetId
    }
    customNetworkInterfaceName: 'nic-${application}mysql-${environment}-${location}-001'
    privateLinkServiceConnections:[{
      name: 'pl-mysql-${environment}-${location}-001'
      properties:{
        privateLinkServiceId: mySQLServer.id
        groupIds: [
          'mysqlServer'
        ]
        privateLinkServiceConnectionState: {
          status: 'Approved'
          description: 'Auto-Approved'
          actionsRequired: 'None'
        }
      }
    }]
  }
}

// MySQL private dns zone
resource privateMySQLDNSZone 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: mysqlURL
  location: 'global'
}

// MySQL private dns zone virtual network link
resource privateMySQLDNSZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  name: 'vnl-mysql-${application}-${environment}-${location}-001'
  location: 'global'
  parent: privateMySQLDNSZone
  properties:{
    registrationEnabled: false
    virtualNetwork:{
      id: virtualNetworkId
    }
  }
}

// MySQL private dns zone group
resource privateMySQLDNSZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2022-11-01' = {
  name: 'default'
  parent: privateMySQLEndpoint
  properties:{
    privateDnsZoneConfigs:[
      {
        name: mysqlURL
        properties:{
          privateDnsZoneId: privateMySQLDNSZone.id
        }
      }
    ]
  }
}
