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
    