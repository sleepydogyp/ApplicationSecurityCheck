# -*- coding: utf_8 -*-

'''
动态注册广播暴露风险
'''


from data_vulnerability import VulnerabilityData
from formatClassAndMethod import formatClassAndMethod

from statementParser import ConstParser, InvokeParser


class DynamicBroadcast:

    constMap = dict()

    def checkInvoke(self, clazzName, methodName, invokeParser):
        if 'registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;' in invokeParser.body:
            VulnerabilityData.dynamicBroadcast.add(formatClassAndMethod(clazzName, methodName))
        elif 'registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;)Landroid/content/Intent;' in invokeParser.body:
            if len(invokeParser.arg) > 3 and invokeParser.arg[3] in self.constMap.keys() and '0x0' in self.constMap[invokeParser.arg[3]]:
                VulnerabilityData.dynamicBroadcast.add(formatClassAndMethod(clazzName, methodName))

    def checkConst(self, statement):
        if statement.startswith('const'):
            constParser = ConstParser()
            constParser.parse(statement)
            if constParser.arg in self.constMap:
                self.constMap[constParser.arg] = constParser.value
            else:
                self.constMap[constParser.arg] = self[constParser.value]

    def checkResult(self):
        self.constMap.clear()