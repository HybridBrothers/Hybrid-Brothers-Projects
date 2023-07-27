using 'main.bicep'

param application = 'blog'
param environment = 'test'
param vnetConfig = {
  name: 'blog'
  addressPrefixes: [
    '10.0.0.0/16'
  ]
  subnets: [
    {
      name: 'containerapps'
      addressPrefix: '10.0.0.0/22'
    }
  ]
}
param acaConfig = {
  url: 'blog.xxx.com'
  storageAccountName: 'abcdefghikjlmnopqrstuvwxyz'
  smtpUserName: 'postmaster@xxx.com'
}
param dbConfig = {
  serverName: 'abcdefghikjlmnopqrstuvwxyz'
  username: 'blogadministrator'
  dbname: 'blogdatabase'
}
