# -*- coding: utf_8 -*-

'''
动态加载DEX文件
'''

from data_vulnerability import VulnerabilityData
from formatClassAndMethod import formatClassAndMethod

from statementParser import ConstParser, InvokeParser


class DynamicLoadDex:

    constMap = dict()

    def checkInvoke(self, clazzName, methodName, invokeParser):
        if 'Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V' in invokeParser:
            if len(invokeParser.arg) > 2 and invokeParser.arg[2] in self.constMap.keys() and '/sdcard' in self.constMap[invokeParser.arg[2]]:
                VulnerabilityData.dynamicLoadDex.add(formatClassAndMethod(clazzName, methodName))

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
