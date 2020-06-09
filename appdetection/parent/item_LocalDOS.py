# -*- coding: utf_8 -*-

'''
本地拒绝服务攻击
'''

from parent.data_vulnerability import VulnerabilityData
from formatClassAndMethod import formatClassAndMethod

from statementParser import InvokeParser


class LocalDOS:

    def checkInvoke(self, clazzName, methodName, invokeParser):
        if 'Landroid/content/Intent;->get' in invokeParser.body and 'Extra(' in invokeParser.body:
            VulnerabilityData.localDOS.add(formatClassAndMethod(clazzName, methodName))
