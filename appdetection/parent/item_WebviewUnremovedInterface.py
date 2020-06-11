# -*- coding: utf_8 -*-

'''
未移除有风险的WebView接口
'''

from parent.data_vulnerability import VulnerabilityData
from formatClassAndMethod import formatClassAndMethod

from statementParser import ConstParser, InvokeParser

# TODO:需要做方法间分析


class WebViewUnremovedInterface:

    def __init__(self, vulnerabilityData):
        self.vulnerabilityData = vulnerabilityData

    argMaps = dict()
    isRemoveJavascriptInterface = False
    isWebviewSetting = False
    searchBoxJavaBridge_flag = False
    accessibilityTraversal_flag = False
    accessibility_flag = False

    def checkInvoke(self, invokeParser):
        if 'Landroid/webkit/WebView;->removeJavascriptInterface(Ljava/lang/String;)V' in invokeParser.body:
            self.isRemoveJavascriptInterface = True
            methodArgs = invokeParser.arg
            if len(methodArgs) > 1:
                if methodArgs[1] in self.argMaps:
                    if self.argMaps[methodArgs[1]] == 'searchBoxJavaBridge_':
                        self.searchBoxJavaBridge_flag = True
                    elif self.argMaps[methodArgs[1]] == 'accessibilityTraversal':
                        self.accessibilityTraversal_flag = True
                    elif self.argMaps[methodArgs[1]] == 'accessibility':
                        self.accessibility_flag = True

    def checkConst(self, statement):
        if statement.startswith('const-string'):
            constParser = ConstParser()
            constParser.parse(statement)
            if constParser.value == 'searchBoxJavaBridge_' or constParser.value == 'accessibilityTraversal' or constParser.value == 'accessibility':
                self.argMaps[constParser.arg] = constParser.value

    def checkResult(self, clazzName, methodName):
        if self.isRemoveJavascriptInterface:
            if not (self.searchBoxJavaBridge_flag and self.accessibility_flag and self.accessibility_flag):
                self.vulnerabilityData.webviewUnremovedInterface.add(formatClassAndMethod(clazzName, methodName))
        self.searchBoxJavaBridge_flag = False
        self.accessibility_flag = False
        self.accessibilityTraversal_flag = False
        self.argMaps.clear()
