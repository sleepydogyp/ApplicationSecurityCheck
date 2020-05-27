# -*- coding: utf_8 -*-

import logging

from appdetection.parent.data.appBaseInfo import AppBaseData

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

logging.basicConfig(
    filename='app.log',
    level=logging.DEBUG,
    format='%(asctime)s %(filename)s[line:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d, %H:%M:%S')
namespace = '{http://schemas.android.com/apk/res/android}'


def parseManifest(filePath):
    if (filePath.endswith('.xml')):
        elementTree = ET.parse(filePath)
        root = elementTree.getroot()
        AppBaseData.packageName = root.get('package')
        uses_permissions = set()
        permissions = set()
        for child in root:
            # 1. uses-permission
            if (child.tag in 'uses_permission'):
                uses_permissions.add(child.attrib[namespace + 'name'])
            # 2. permission
            elif (child.tag in 'permission'):
                permissionAttrib = {}
                permissionAttrib['name'] = child.attrib[namespace + 'name']
                permissionAttrib['protectionLevel'] = child.attrib[
                    namespace + 'protectionLevel']
                permissions.add(permissionAttrib)
            # 3. application
            elif (child.tag == 'application'):
                '''
                debuggable缺省值为false,当显示设置为true时，表示存在风险
                allowBackup缺省值为true, 必须显示设置为false，才没有风险
                '''
                # debuggable
                if child.get('debuggable') in "true":
                    AppBaseData.debuggable = True
                else:
                    AppBaseData.debuggable = False
                # allowBackup
                if child.get('allowBackup') in "false":
                    AppBaseData.allowBackup = False
                else:
                    AppBaseData.allowBackup = True

                # four components and exported components
                exportedActivities = set()
                exportedServices = set()
                exportedReceivers = set()
                exportedProviders = set()
                activities = set()
                services = set()
                receivers = set()
                providers = set()
                for component in child:
                    if (component.tag == 'Activity'):
                        activityName = component.attrib[namespace + 'name']
                        activities.add(activityName)
                        if isExported(component):
                            exportedActivities.add(activityName)
                        if isMainActivity(component):
                            # mainActivity
                            AppBaseData.mainActivity = activityName
                    elif (component.tag == 'service'):
                        serviceName = component.attrib[namespace + 'name']
                        services.add(serviceName)
                        if isExported(component):
                            exportedServices.add(serviceName)
                    elif (component.tag == 'receiver'):
                        receiverName = component.attrib[namespace + 'name']
                        receivers.add(receiverName)
                        if isExported(component):
                            exportedReceivers.add(receiverName)
                    elif (component.tag == 'provider'):
                        providerName = component.attrib[namespace + 'name']
                        providers.add(providerName)
                        if isExported(component):
                            exportedProviders.add(providerName)
                AppBaseData.activities = activities
                AppBaseData.services = services
                AppBaseData.receivers = receivers
                AppBaseData.providers = providers
                AppBaseData.exportedActivities = exportedActivities
                AppBaseData.exportedServices = exportedServices
                AppBaseData.exportedReceivers = exportedReceivers
                AppBaseData.exportedProviders = exportedProviders
        AppBaseData.uses_permissions = uses_permissions
        AppBaseData.permissions = permissions
    else:
        logging.error('cannot find AndroidManifest.xml!')


def isMainActivity(elem):
    intent_filter = elem.find('intent-filter')
    if intent_filter is not None:
        action = intent_filter.find('action')
        category = intent_filter.find('category')
        if action is not None and category is not None \
            and action.attrib[namespace + 'name'] \
                in 'android.intent.action.MAIN' \
                and category.attrib[namespace + 'name'] in \
                'android.intent.category.LAUNCHER':
            return True
    return False


def isExported(elem):
    attribs = elem.items()
    itemName = namespace + 'exported'
    for item in attribs:
        if itemName.find(item[0]):
            exported = item[1]
            break
    # 如果包含intent-filter默认为true, 否则默认为false
    intent_filter = elem.find('intent-filter')
    if intent_filter is not None and exported in 'false':
        return False
    elif intent_filter is None and (exported is None or exported in 'false'):
        return False
    return True