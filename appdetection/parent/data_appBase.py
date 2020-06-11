# -*- coding: utf_8 -*-

'''
存放应用基本信息
'''


class AppBaseData:

    appName = ''
    packageName = ''
    versionName = ''
    appIcon = ''
    mainActivity = ''

    activities = set()
    services = set()
    receivers = set()
    providers = set()
    exportedActivities = set()
    exportedServices = set()
    exportedReceivers = set()
    exportedProviders = set()
    uses_permissions = set()
    permissions = set()

    debuggable = False
    allowBackup = False
    isDebugCert = False

    def outputAppBaseData(self):
        appBaseDataDict = dict()
        appBaseDataDict['appName'] = self.appName
        appBaseDataDict['packageName'] = self.packageName
        appBaseDataDict['versionName'] = self.versionName
        appBaseDataDict['appIcon'] = self.appIcon
        appBaseDataDict['mainActivity'] = self.mainActivity

        appBaseDataDict['activities'] = self.activities
        appBaseDataDict['services'] = self.services
        appBaseDataDict['receivers'] = self.receivers
        appBaseDataDict['providers'] = self.providers
        appBaseDataDict['exportedActivities'] = self.exportedActivities
        appBaseDataDict['exportedServices'] = self.exportedServices
        appBaseDataDict['exportedReceivers'] = self.exportedReceivers
        appBaseDataDict['exportedProviders'] = self.exportedProviders
        appBaseDataDict['uses_permissions'] = self.uses_permissions
        appBaseDataDict['permissions'] = self.permissions

        appBaseDataDict['debuggable'] = self.debuggable
        appBaseDataDict['allowBackup'] = self.allowBackup
        appBaseDataDict['isDebugCert'] = self.isDebugCert


    