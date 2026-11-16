// Gantry on Azure Container Apps with Azure Database for PostgreSQL flexible server as its store.
// A first try or a small team: one replica, a Burstable database. The admin key is printed once in the container's
// logs. The Deploy to Azure button uses azuredeploy.json, built from this file: az bicep build --file main.bicep --outfile azuredeploy.json
// Production: https://gantry-docs.enterplace.dev/deploy/azure/

@description('Name prefix for every resource.')
param name string = 'gantry'

@description('Where everything runs.')
param location string = resourceGroup().location

@description('The provider whose key you give below. Add others later in the console.')
@allowed(['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GEMINI_API_KEY'])
param providerKeyName string = 'OPENAI_API_KEY'

@description('Your provider API key, kept as a Container Apps secret.')
@secure()
param providerKey string

@description('The Gantry image. Pin a version for anything that lasts.')
param image string = 'ghcr.io/eliransu/gantry:latest'

@description('The database password. Leave the default: a new random value, used only inside DATABASE_URL.')
@secure()
param databasePassword string = newGuid()

var suffix = uniqueString(resourceGroup().id, name)

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${name}-logs-${suffix}'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

resource database 'Microsoft.DBforPostgreSQL/flexibleServers@2024-08-01' = {
  name: '${name}-db-${suffix}'
  location: location
  sku: {
    name: 'Standard_B1ms'
    tier: 'Burstable'
  }
  properties: {
    version: '16'
    administratorLogin: 'gantry'
    administratorLoginPassword: databasePassword
    storage: { storageSizeGB: 32 }
    backup: { backupRetentionDays: 7, geoRedundantBackup: 'Disabled' }
    highAvailability: { mode: 'Disabled' }
    network: { publicNetworkAccess: 'Enabled' }
  }
}

resource gantryDatabase 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2024-08-01' = {
  parent: database
  name: 'gantry'
}

// 0.0.0.0 to 0.0.0.0 admits Azure services only, Container Apps among them. The password and TLS guard the rest.
resource allowAzure 'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules@2024-08-01' = {
  parent: database
  name: 'AllowAzureServices'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}

resource environment 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${name}-env-${suffix}'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logs.properties.customerId
        sharedKey: logs.listKeys().primarySharedKey
      }
    }
  }
}

resource app 'Microsoft.App/containerApps@2024-03-01' = {
  name: name
  location: location
  dependsOn: [gantryDatabase, allowAzure]
  properties: {
    managedEnvironmentId: environment.id
    configuration: {
      ingress: {
        external: true
        targetPort: 8080
        transport: 'http'
      }
      secrets: [
        {
          // The server's certificate chains to DigiCert Global Root G2, among the roots built into Gantry, so the
          // default sslmode (verify-full) holds.
          name: 'database-url'
          value: 'postgres://gantry:${databasePassword}@${database.properties.fullyQualifiedDomainName}:5432/gantry'
        }
        {
          name: 'provider-key'
          value: providerKey
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'gantry'
          image: image
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: [
            { name: 'DATABASE_URL', secretRef: 'database-url' }
            { name: providerKeyName, secretRef: 'provider-key' }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: { path: '/healthz', port: 8080 }
              periodSeconds: 10
            }
          ]
        }
      ]
      // One replica: it keeps its audit chain on its own disk, and keys and the policy in the store.
      scale: {
        minReplicas: 1
        maxReplicas: 1
      }
    }
  }
}

output consoleUrl string = 'https://${app.properties.configuration.ingress.fqdn}/console'
output gatewayUrl string = 'https://${app.properties.configuration.ingress.fqdn}'
output adminKeyLogs string = 'az containerapp logs show --name ${name} --resource-group ${resourceGroup().name} --type console --tail 300 | grep GANTRY_KEY'
