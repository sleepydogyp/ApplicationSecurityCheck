# -*- coding: utf_8 -*-

'''
ContentProvider目录遍历漏洞
'''

from parent.data_appBase import AppBaseData
from data_vulnerability import VulnerabilityData
from formatClassAndMethod import formatClassAndMethod

from statementParser import ConstParser, InvokeParser


class ContentProviderDirTraverse:

    def checkInvoke(self, clazzName, methodName, invokeParser):
        if 'openFile(' in invokeParser.body and '([Landroid/net/Uri;Ljava/lang/String;])' in invokeParser.body and 'Landroid/os/ParcelFileDescriptor;' in invokeParser.body:
            clazzName = clazzName.subString(1).replace('/', '.')
            if clazzName in AppBaseData.exportedProviders:
                VulnerabilityData.contentProviderDirTraverse.add(formatClassAndMethod(clazzName, methodName))


 