//--------------------
// Parameters
//--------------------
param vnetConfig object
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
// Virtual Network
//--------------------
resource virtualNetwork 'Microsoft.Network/virtualNetworks@2022-11-01' = {
  name: 'vnet-${application}-${environment}-${location}-001'
  location: location
  properties:{
    addressSpace: {
      addressPrefixes: vnetConfig.addressPrefixes
    }
    subnets: [for subnet in vnetConfig.subnets: {
        name: 'snet-${subnet.name}-${environment}-${location}-001'
        properties:{
          addressPrefix: subnet.addressPrefix
        }
      }]
  }
}
