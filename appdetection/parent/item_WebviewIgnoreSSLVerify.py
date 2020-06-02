# -*- coding: utf_8 -*-

'''
WebView忽略SSL证书验证错误漏洞
'''


from data_vulnerability import VulnerabilityData
from formatClassAndMethod import formatClassAndMethod
from detecctItemsEntry import MethodInfo, ClazzInfo
from statementParser import InvokeParser

import logging

logging.basicConfig(
    filename='app.log',
    encoding='utf-8',
    format='%(asctime)s %(filename)s[line:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d, %H:%M:%S')


class WebviewIgnoreSSLVerify:

    def checkInvoke(self, clazzInfo, methodInfo, invokeParser):
        methodName = methodInfo.methodName
        methodArgs = methodInfo.methodArgs
        methodReturn = methodInfo.methodReturn
        if clazzInfo.superClazz != 'Landroid/webkit/WebViewClient;':
            return
        if methodName == 'onReceivedSslError' and methodArgs == 'Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;Landroid/net/http/SslError;' and methodReturn == 'V':
            if invokeParser.operation == 'invoke-virtual' and invokeParser.body == 'Landroid/webkit/SslErrorHandler;->proceed()V':
                VulnerabilityData.WebviewIgnoreSSLVerify.add(formatClassAndMethod(clazzInfo.clazzName, methodName))




