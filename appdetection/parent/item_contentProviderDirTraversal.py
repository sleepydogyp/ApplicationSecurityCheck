# -*- coding: utf_8 -*-

'''
Content Provider目录遍历漏洞
'''

import logging
from data_appBase import AppBaseData
from data_vulnerability import VulnerabilityData
from formatClassAndMethod import formatClassAndMethod

logging.basicConfig(
    filename='app.log',
    encoding='utf-8',
    format='%(asctime)s %(filename)s[line:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d, %H:%M:%S')


class ContentProviderDirTraversal:

    def check(self, calssName, methodName, args, returnType):
        if calssName in AppBaseData.exportedProvider:
            if args == 'Landroid/net/Uri;Ljava/lang/String;' and returnType == 'Landroid/os/ParcelFileDescriptor;':
                VulnerabilityData.contentProviderDirTraversal.add(formatClassAndMethod(calssName, methodName))


