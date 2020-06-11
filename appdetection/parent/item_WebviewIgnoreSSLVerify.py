# -*- coding: utf_8 -*-

'''
WebView忽略SSL证书验证错误漏洞
'''


from parent.data_vulnerability import VulnerabilityData
from formatClassAndMethod import formatClassAndMethod
from clazzAndMethodInfo import MethodInfo, ClazzInfo
from statementParser import InvokeParser


class WebviewIgnoreSSLVerify:

    def __init__(self, vulnerabilityData):
        self.vulnerabilityData = vulnerabilityData

    def checkInvoke(self, clazzInfo, methodInfo, invokeParser):
        methodName = methodInfo.methodName
        methodArgs = methodInfo.methodArgs
        methodReturn = methodInfo.methodReturn
        if clazzInfo.superClazz != 'Landroid/webkit/WebViewClient;':
            return
        if methodName == 'onReceivedSslError' and methodArgs == 'Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;Landroid/net/http/SslError;' and methodReturn == 'V':
            if invokeParser.operation == 'invoke-virtual' and invokeParser.body == 'Landroid/webkit/SslErrorHandler;->proceed()V':
                self.vulnerabilityData.webviewIgnoreSSLVerify.add(formatClassAndMethod(clazzInfo.clazzName, methodName))




