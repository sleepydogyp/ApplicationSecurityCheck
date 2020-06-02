# -*- coding: utf_8 -*-


'''
WebView明文存储密码, WebView File域同源绕过
'''

from data_vulnerability import VulnerabilityData
from formatClassAndMethod import formatClassAndMethod

from statementParser import ConstParser, InvokeParser


class WebViewSavePasswordAndFileAccess:

    constMap = dict()
    isSetSavePassWordFalse = False
    isFileAccess = False

    def checkInvoke(self, invokeParser):
        if 'Landroid/webkit/WebSettings;->setSavePassword(Z)V' in invokeParser.body:
            if len(invokeParser.arg) > 1 and invokeParser.arg[1] in self.constMap:
                if '0x0' in self.constMap[invokeParser.arg[1]]:
                    self.isSetSavePassWordFalse = True
        elif 'Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V' in invokeParser.body or 'Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V' in invokeParser.body:
            if len(invokeParser.arg) > 1 and invokeParser.arg[1] in self.constMap:
                if '0x1' in self.constMap[invokeParser.arg[1]]:
                    self.isFileAccess = True

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
            VulnerabilityData.webViewSavePassword.add()
        if self.isFileAccess:
            VulnerabilityData.webViewFileAccess.add(formatClassAndMethod(clazzName, methodName))
        self.constMap.clear()
        self.isSetSavePassWordFalse = False
        self.isFileAccess = False