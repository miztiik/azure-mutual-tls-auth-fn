// SET MODULE DATE
param module_metadata object = {
  module_last_updated: '2023-12-09'
  owner: 'miztiik@github'
}

param deploymentParams object
param vnet_params object

param tags object = resourceGroup().tags

param vnet_address_prefixes object = {
  addressPrefixes: [
    '10.0.0.0/16'
  ]
}
param webSubnet01Cidr string = '10.0.0.0/24'
param webSubnet02Cidr string = '10.0.1.0/24'
param appSubnet01Cidr string = '10.0.2.0/24'
param appSubnet02Cidr string = '10.0.3.0/24'
param dbSubnet01Cidr string = '10.0.4.0/24'
param dbSubnet02Cidr string = '10.0.5.0/24'

/*
param flex_db_subnet_cidr string = '10.0.6.0/24'
param dbSubnet02Cidr string = '10.0.7.0/24'
param dbSubnet02Cidr string = '10.0.8.0/24'
*/

param pvt_endpoint_subnet_cidr string = '10.0.10.0/24'

param gateway_subnet_cidr string = '10.0.20.0/24'
param fw_subnet_cidr string = '10.0.30.0/24'

param k8s_subnet_cidr string = '10.0.128.0/19'
// param k8s_service_cidr string = '10.0.191.0/24' // Do not change this

resource r_vnet 'Microsoft.Network/virtualNetworks@2021-05-01' = {
  name: '${vnet_params.vnet_name_prefix}_${deploymentParams.loc_short_code}_${deploymentParams.global_uniqueness}_vnet'
  location: deploymentParams.location
  tags: tags
  properties: {
    addressSpace: vnet_address_prefixes
    subnets: [
      {
        name: 'webSubnet01'
        properties: {
          addressPrefix: webSubnet01Cidr
        }
      }
      {
        name: 'webSubnet02'
        properties: {
          addressPrefix: webSubnet02Cidr
        }
      }
      {
        name: 'appSubnet01'
        properties: {
          addressPrefix: appSubnet01Cidr
        }
      }
      {
        name: 'appSubnet02'
        properties: {
          addressPrefix: appSubnet02Cidr
        }
      }
      {
        name: 'dbSubnet01'
        properties: {
          addressPrefix: dbSubnet01Cidr
        }
      }
      {
        name: 'dbSubnet02'
        properties: {
          addressPrefix: dbSubnet02Cidr
        }
      }
      {
        name: 'pvt_endpoint_subnet'
        properties: {
          addressPrefix: pvt_endpoint_subnet_cidr
        }
      }
      {
        name: 'k8s_subnet'
        properties: {
          addressPrefix: k8s_subnet_cidr
        }
      }
      {
        name: 'gw_subnet'
        properties: {
          addressPrefix: gateway_subnet_cidr
        }
      }
      {
        name: 'fw_subnet'
        properties: {
          addressPrefix: fw_subnet_cidr
        }
      }
    ]
  }
}

// resource ng 'Microsoft.Network/natGateways@2021-03-01' = if (nat_gateway) {
//   name: 'ng-${name}'
//   location: deploymentParams.location
//   tags: tags
//   sku: {
//     name: 'Standard'
//   }
//   properties: {
//     idleTimeoutInMinutes: 4
//     publicIpAddresses: [
//       {
//         id: pip.id
//       }
//     ]
//   }
// }

// resource pip 'Microsoft.Network/publicIPAddresses@2021-03-01' = if (natGateway) {
//   name: 'pip-ng-${name}'
//   location: deploymentParams.location
//   tags: tags
//   sku: {
//     name: 'Standard'
//   }
//   properties: {
//     publicIPAllocationMethod: 'Static'
//   }
// }

// OUTPUTS
output module_metadata object = module_metadata

output vnetId string = r_vnet.id
output vnetName string = r_vnet.name
output vnetSubnets array = r_vnet.properties.subnets

output dbSubnet01Id string = r_vnet.properties.subnets[4].id
output dbSubnet02Id string = r_vnet.properties.subnets[5].id

output pvt_endpoint_subnet string = r_vnet.properties.subnets[6].id
