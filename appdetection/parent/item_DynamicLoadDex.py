# -*- coding: utf_8 -*-

'''
动态加载DEX文件
'''

from parent.data_vulnerability import VulnerabilityData
from formatClassAndMethod import formatClassAndMethod

from statementParser import ConstParser, InvokeParser


class DynamicLoadDex:

    def __init__(self, vulnerabilityData):
        self.vulnerabilityData = vulnerabilityData

    constMap = dict()

    def checkInvoke(self, clazzName, methodName, invokeParser):
        if 'Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V' in invokeParser.body:
            if len(invokeParser.arg) > 2 and invokeParser.arg[2] in self.constMap.keys() and '/sdcard' in self.constMap[invokeParser.arg[2]]:
                self.vulnerabilityData.dynamicLoadDex.add(formatClassAndMethod(clazzName, methodName))

    def checkConst(self, statement):
        if statement.startswith('const'):
            constParser = ConstParser()
            constParser.parse(statement)
            self.constMap[constParser.arg] = constParser.value

    def checkResult(self):
        self.constMap.clear()
