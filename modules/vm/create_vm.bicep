// SET MODULE DAvm_paramsTE
param module_metadata object = {
  module_last_updated: '2023-06-04'
  owner: 'miztiik@github'
}

param deploymentParams object
param tags object

param uami_name_vm string

param sa_name string
param blob_container_name string
param misc_sa_name string

param logAnalyticsPayGWorkspaceId string

param linDataCollectionEndpointId string
param storeEventsDcrId string
param automationEventsDcrId string

param vm_params object
param vnetName string
param vmName string = replace('${vm_params.name_prefix}-${deploymentParams.loc_short_code}-${deploymentParams.enterprise_name_suffix}-${deploymentParams.global_uniqueness}', '_', '-')

param dnsLabelPrefix string = toLower('${vm_params.name_prefix}-${deploymentParams.global_uniqueness}-${uniqueString(resourceGroup().id, vmName)}')
// param publicIpName string = '${vm_params.name_prefix}-${deploymentParams.global_uniqueness}-PublicIp'

param add_to_appln_gw bool = false
param appln_gw_name string = 'appgw'
param appln_gw_back_end_pool_name string = 'appgw-backend-pool'

param no_of_vms int = 1

// var userDataScript = base64(loadTextContent('./bootstrap_scripts/deploy_app.sh'))
var userDataScript = loadFileAsBase64('./bootstrap_scripts/deploy_app.sh')

// @description('VM auth')
// @allowed([
//   'sshPublicKey'
//   'password'
// ])
// param authType string = 'password'

var LinuxConfiguration = {
  disablePasswordAuthentication: true
  ssh: {
    publickeys: [
      {
        path: '/home/${vm_params.admin_username}/.ssh/authorized_keys'
        keyData: vm_params.admin_password
      }
    ]
  }
}

// Resource References
resource r_blob_ref 'Microsoft.Storage/storageAccounts/blobServices/containers@2021-04-01' existing = {
  name: '${sa_name}/default/${blob_container_name}'
}

// Reference existing User-Assigned Identity
resource r_uami_ref 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: uami_name_vm
}

// Create Public IPs
resource r_publicIp 'Microsoft.Network/publicIPAddresses@2022-05-01' = [for i in range(0, no_of_vms): {
  name: '${vmName}-pip-${i}'
  location: deploymentParams.location
  tags: tags
  sku: {
    name: vm_params.public_ip_sku
  }
  properties: {
    publicIPAllocationMethod: vm_params.public_ip_allocation_method
    publicIPAddressVersion: 'IPv4'
    deleteOption: 'Delete'
    dnsSettings: {
      domainNameLabel: '${dnsLabelPrefix}-${i}'
    }
  }
}]

resource r_webSg 'Microsoft.Network/networkSecurityGroups@2021-05-01' = {
  name: 'webSg'
  location: deploymentParams.location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'AllowInboundSsh'
        properties: {
          priority: 250
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }
      {
        name: 'HTTP'
        properties: {
          priority: 200
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '80'
        }
      }
      {
        name: 'AllowHTTPInbound'
        properties: {
          priority: 100
          access: 'Allow'
          direction: 'Inbound'
          protocol: '*'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '80'
        }
      }

      {
        name: 'Outbound_Allow_All'
        properties: {
          priority: 300
          protocol: '*'
          access: 'Allow'
          direction: 'Outbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      {
        name: 'AzureResourceManager'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: 'AzureResourceManager'
          access: 'Allow'
          priority: 160
          direction: 'Outbound'
        }
      }
      {
        name: 'AzureStorageAccount'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: 'Storage.${deploymentParams.location}'
          access: 'Allow'
          priority: 170
          direction: 'Outbound'
        }
      }
      {
        name: 'AzureFrontDoor'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: 'AzureFrontDoor.FrontEnd'
          access: 'Allow'
          priority: 180
          direction: 'Outbound'
        }
      }
    ]
  }
}

//
resource r_webSgNsgDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: r_webSg
  name: 'default'
  properties: {
    workspaceId: logAnalyticsPayGWorkspaceId
    logs: [
      {
        category: 'NetworkSecurityGroupEvent'
        enabled: true
        retentionPolicy: {
          enabled: false
          days: 0
        }
      }
      {
        category: 'NetworkSecurityGroupRuleCounter'
        enabled: true
        retentionPolicy: {
          enabled: false
          days: 0
        }
      }
    ]
  }
}

// Create NICs for the VM
resource r_nics_01 'Microsoft.Network/networkInterfaces@2021-08-01' = [for i in range(0, no_of_vms): {
  name: '${vmName}-nic-${i}'
  location: deploymentParams.location
  tags: tags
  properties: {
    ipConfigurations: [
      {
        name: '${vmName}-ipconfig-${i}'
        properties: {
          primary: true
          privateIPAddressVersion: 'IPv4'
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', vnetName, vm_params.vm_subnet_name)
          }
          // loadBalancerBackendAddressPools: [
          //   {
          //     id: resourceId('Microsoft.Network/loadBalancers/backendAddressPools', lb_name, lb_back_end_pool_name)
          //   }
          //   {
          //     id: resourceId('Microsoft.Network/loadBalancers/backendAddressPools', lb_name, lb_back_end_pool_name_outbound)
          //   }
          // ]
          applicationGatewayBackendAddressPools: add_to_appln_gw ? [
            {
              id: resourceId('Microsoft.Network/applicationGateways/backendAddressPools', appln_gw_name, appln_gw_back_end_pool_name)
            }
          ] : null
          publicIPAddress: {
            id: r_publicIp[i].id
          }
        }
      }
    ]
    networkSecurityGroup: {
      id: r_webSg.id
    }
  }
}]

// Add permissions to the custom identity to write to the blob storage
// Azure Built-In Roles Ref: https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles
param blobOwnerRoleId string = 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'

var blobPermsConditionStr = '((!(ActionMatches{\'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read\'}) AND !(ActionMatches{\'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write\'}) ) OR (@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals \'${blob_container_name}\'))'

// Refined Scope with conditions
// https://learn.microsoft.com/en-us/azure/templates/microsoft.authorization/roleassignments?pivots=deployment-language-bicep

resource r_attach_perms_to_role_BlobOwner 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid('r_attach_perms_to_role_BlobOwner', r_uami_ref.id, blobOwnerRoleId)
  scope: r_blob_ref
  properties: {
    description: 'Blob Owner Permission to ResourceGroup scope'
    roleDefinitionId: resourceId('Microsoft.Authorization/roleDefinitions', blobOwnerRoleId)
    principalId: r_uami_ref.properties.principalId
    conditionVersion: '2.0'
    condition: blobPermsConditionStr
    principalType: 'ServicePrincipal'
    // https://learn.microsoft.com/en-us/azure/role-based-access-control/troubleshooting?tabs=bicep#symptom---assigning-a-role-to-a-new-principal-sometimes-fails
  }
}

/*
// Add Monitoring Metrics Publisher Role to the custom identity
param metricsPublisherRoleId string = '3913510d-42f4-4e42-8a64-420c390055eb'

resource r_attach_perms_to_role_MetricsPublisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid('r_attach_perms_to_role_MetricsPublisher', r_uami_ref.id, metricsPublisherRoleId)
  scope: resourceGroup()
  properties: {
    description: 'Monitoring Metrics Publisher Permission to ResourceGroup scope'
    roleDefinitionId: resourceId('Microsoft.Authorization/roleDefinitions', metricsPublisherRoleId)
    principalId: r_uami_ref.properties.principalId
    principalType: 'ServicePrincipal'
    // https://learn.microsoft.com/en-us/azure/role-based-access-control/troubleshooting?tabs=bicep#symptom---assigning-a-role-to-a-new-principal-sometimes-fails
  }
}

*/

// Create the VMs
resource r_vms 'Microsoft.Compute/virtualMachines@2021-11-01' = [for i in range(0, no_of_vms): {
  name: '${vmName}-${i}'
  location: deploymentParams.location
  tags: tags
  zones: [
    string((i % 3) + 1)
  ]
  identity: {
    // type: 'SystemAssigned'
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${r_uami_ref.id}': {}
    }
  }
  properties: {
    hardwareProfile: {
      vmSize: vm_params.vm_size
    }
    osProfile: {
      computerName: '${vmName}-${i}'
      adminUsername: vm_params.admin_username
      adminPassword: vm_params.admin_password.secure_string
      linuxConfiguration: ((vm_params.auth_type == 'password') ? null : LinuxConfiguration)
    }
    storageProfile: {
      imageReference: ((vm_params.is_ubuntu == true) ? ({
        publisher: 'Canonical'
        offer: '0001-com-ubuntu-server-jammy'
        sku: '22_04-lts-gen2'
        version: 'latest'
      }) : ({
        publisher: 'RedHat'
        offer: 'RHEL'
        sku: '91-gen2'
        version: 'latest'
      }))
      osDisk: {
        createOption: 'FromImage'
        name: '${vmName}-osDisk-${i}'
        caching: 'ReadWrite'
        deleteOption: 'Delete'
        diskSizeGB: 128
        managedDisk: {
          storageAccountType: 'StandardSSD_LRS'
        }
      }
      dataDisks: [
        {
          createOption: 'Empty'
          name: '${vmName}-DataDisk-${i}'
          caching: 'ReadWrite'
          deleteOption: 'Delete'
          lun: 13
          diskSizeGB: 2
          managedDisk: {
            storageAccountType: 'StandardSSD_LRS'
            // storageAccountType: 'PremiumV2_LRS' // Apparently needs zones to be defined and AZURE capacity issues - ^.^
          }
        }
      ]
    }
    networkProfile: {
      networkInterfaces: [
        {
          // id: resourceId('Microsoft.Network/networkInterfaces', '${projectName}-vm${i}-networkInterface')
          id: resourceId('Microsoft.Network/networkInterfaces', '${vmName}-nic-${i}')
        }
      ]
    }
    securityProfile: {
      // encryptionAtHost: true
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true
        storageUri: 'https://${misc_sa_name}.blob.${environment().suffixes.storage}'
      }
    }
    userData: userDataScript
  }
  dependsOn: [
    r_nics_01
  ]
}]

// INSTALL Azure Monitor Agent
resource AzureMonitorLinuxAgent 'Microsoft.Compute/virtualMachines/extensions@2021-07-01' = [for i in range(0, no_of_vms): if (vm_params.is_linux) {
  parent: r_vms[i]
  name: 'AzureMonitorLinuxAgent'
  location: deploymentParams.location
  properties: {
    publisher: 'Microsoft.Azure.Monitor'
    type: 'AzureMonitorLinuxAgent'
    enableAutomaticUpgrade: true
    autoUpgradeMinorVersion: true
    typeHandlerVersion: '1.25'
    settings: {
      'identifier-name': 'mi_res_id' // Has to be this value
      // 'identifier-value': r_vm.identity.principalId
      'identifier-value': r_uami_ref.id
    }
  }
}]

@description('Associate Data Collection Endpoint to VM')
// Apparently you cannot name this resource and also it cannot be clubbed with DCR association
resource r_associateDce_To_Vm 'Microsoft.Insights/dataCollectionRuleAssociations@2021-09-01-preview' = [for i in range(0, no_of_vms): {
  name: 'configurationAccessEndpoint'
  scope: r_vms[i]
  properties: {
    dataCollectionEndpointId: linDataCollectionEndpointId
    // dataCollectionRuleId: storeEventsDcrId
    description: 'Send Custom logs to DCR'
  }
}]

@description('Associate Store Events DCR to VM')
resource r_associatestoreEventsDcr_To_Vm 'Microsoft.Insights/dataCollectionRuleAssociations@2021-09-01-preview' = [for i in range(0, no_of_vms): {
  name: '${vmName}_storeEventsDcr_${deploymentParams.global_uniqueness}'
  scope: r_vms[i]
  properties: {
    // dataCollectionEndpointId: linDataCollectionEndpointId
    dataCollectionRuleId: storeEventsDcrId
    description: 'Send Application Logs to DCR'
  }
}]

@description('Associate Automation Events DCR to VM')
resource r_associateautomationEventsDcr_To_Vm 'Microsoft.Insights/dataCollectionRuleAssociations@2021-09-01-preview' = [for i in range(0, no_of_vms): {
  name: '${vmName}_automationEvents_${deploymentParams.global_uniqueness}'
  scope: r_vms[i]
  properties: {
    // dataCollectionEndpointId: linDataCollectionEndpointId
    dataCollectionRuleId: automationEventsDcrId
    description: 'Send Automation Logs to DCR'
  }
}]

// Associate Diagnostic Settings to VM
resource r_associateDiagnostics_To_Vm 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = [for i in range(0, no_of_vms): {
  name: '${vmName}_diag_${deploymentParams.global_uniqueness}'
  scope: r_vms[i]
  properties: {
    workspaceId: logAnalyticsPayGWorkspaceId
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
        retentionPolicy: {
          enabled: false
          days: 0
        }
      }
    ]
  }
}]

// OUTPUTS
output module_metadata object = module_metadata

output vmNames array = [for i in range(0, no_of_vms): r_vms[i].name]

output adminUsername string = vm_params.admin_username
