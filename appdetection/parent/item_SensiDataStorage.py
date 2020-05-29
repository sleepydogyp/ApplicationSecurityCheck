# -*- coding: utf_8 -*-

'''
敏感数据加密存储
'''

from data_vulnerability import VulnerabilityData
from formatClassAndMethod import formatClassAndMethod

from statementParser import ConstParser, InvokeParser


class SensiDataStorage:

    constMap = dict()
    isWebviewSettings = False
    isSetSavePassWordFalse = False

    def checkInvoke(self, invokeParser):
        if 'Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;' in invokeParser.body:
            self.isWebviewSettings = True
        elif self.isWebviewSettings and 'Landroid/webkit/WebSettings;->setSavePassword(Z)V' in invokeParser.body:
            if len(invokeParser.arg) > 1 and invokeParser.arg[1] in self.constMap:
                if self.constMap[invokeParser.arg[1]] == '0x0':
                    self.isSetSavePassWordFalse = True
                    self.isWebviewSettings = False

    def checkConst(self, statement):
        if statement.startswith('const'):
            constParser = ConstParser()
            constParser.parse(statement)
            if constParser.arg in self.constMap:
                self.constMap[constParser.arg] = constParser.value
            else:
                self.constMap[constParser.arg] = self[constParser.value]

    def checkResult(self, clazzName, methodName):
        if not self.isSetSavePassWordFalse:
            VulnerabilityData.sensiDataStorage.add(formatClassAndMethod(clazzName, methodName))
        self.constMap.clear()
        self.isWebviewSettings = False
        self.isSetSavePassWordFalse = False