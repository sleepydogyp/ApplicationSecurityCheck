# -*- coding: utf_8 -*-

'''
parse smali file 
'''

import logging


from item_contentProviderDirTraversal import ContentProviderDirTraversal
from item_WebviewIgnoreSSLVerify import WebviewIgnoreSSLVerify
from item_HTTPTrustAllSHostname import HTTPSTrustAllHostname
from item_NullCerVerify import NullCerVerify
from item_HostnameNotVerify import HostnameNotVerify
from item_WebviewUnremovedInterface import WebviewUnremovedInterface
from item_AESWeakEncrypt import AESWeakEncrypt

from statementParser import InvokeParser, SgetParser, EndMethodParser


logging.basicConfig(
    filename='app.log',
    level=logging.DEBUG,
    format='%(asctime)s %(filename)s[line:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d, %H:%M:%S')


class MethodInfo:
    methodName = ''
    methodArgs = ''
    methodReturn = ''


class ClazzInfo:
    clazzName = ''
    superClazz = ''
    implements = ''
    methodSet = set()


class DetectItemsEntry:

    clazzInfo = ClazzInfo()
    methodInfo = MethodInfo()

    invokeParser = InvokeParser()
    sgetParser = SgetParser()
    endMethodParser = EndMethodParser()

    contentProviderDirTraversal = ContentProviderDirTraversal()
    webviewIgnoreSSLVerify = WebviewIgnoreSSLVerify()
    hTTPSTrustAllHostname = HTTPSTrustAllHostname()
    nullCerVerify = NullCerVerify()
    hostnameNotVerify = HostnameNotVerify()
    webviewUnremovedInterface = WebviewUnremovedInterface()
    aesWeakEncrypt = AESWeakEncrypt()

    def parseSmaliFile(self, smaliLines):
        isMethod = False
        for line in smaliLines:
            if line == '\n':
                continue
            if line.startswith('.class'):
                temp = line.split(' ')
                self.clazzInfo.className = temp[len(temp) - 1].split(';')[0]
                logging.info('className: ' + self.clazzInfo.clazzName)
            elif line.startswith('.super'):
                self.clazzInfo.superClazz = line - '.super '
            elif line.startswith('.implements '):
                self.clazzInfo.implements = line.split(' ')[1]
            elif line.startswith('.method'):
                isMethod = True
                self.formateMethodInfo(line)
                # Content Provider目录遍历漏洞
                if self.methodInfo.methodName == 'openFile':
                    self.contentProviderDirTraversal.check(self.clazzInfo.clazzName, self.methodInfo.methodName, self.methodInfo.methodArgs, self.methodInfo.methodReturn)
                # HTTPS证书空校验
                elif self.methodInfo.methodName == 'checkServerTrusted' or self.methodInfo.methodName == 'checkClientTrusted':
                    self.nullCerVerify.checkMethod(self.clazzInfo)
                # HTTPS 域名未验证
                elif self.methodInfo.methodName == 'verify' and 'Ljavax/net/ssl/SSLSession;' in self.methodInfo.methodArgs:
                    self.hostnameNotVerify.check(self.clazzInfo)
                
                continue
            elif line == '.end method':
                isMethod = False
                self.endMethodParser.parse(line)
                self.hTTPSTrustAllHostname.check(self.clazzInfo.clazzName, self.methodInfo.methodName, self.endMethodParser)
                self.nullCerVerify.checkResult(self.clazzInfo, self.methodInfo.methodName)
                self.webviewUnremovedInterface.checkResult(self.clazzInfo.clazzName, self.methodInfo.methodName)
                self.methodInfo = MethodInfo()  # method结束，重新初始化MethodInfo
            elif isMethod:  # 方法内
                self.detect(line)

    def detect(self, statement):
        # invoke语句, invoke-direct, invoke-virtual, invoke-static
        if statement.startswith('invoke-'):
            self.invokeParser.parse(statement)
            # WebView忽略SSL证书验证错误漏洞
            self.webviewIgnoreSSLVerify.check(self.clazzInfo, self.methodInfo, self.invokeParser)
            # HTTPS敏感数据劫持
            self.hTTPSTrustAllHostname.check(self.clazzInfo.clazzName, self.methodInfo.methodName, self.invokeParser)
            # 未移除有风险的WebView接口
            self.webviewUnremovedInterface.checkInvoke(self.invokeParser)
            # AES/DES弱加密
            self.aesWeakEncrypt.checkInvoke(self.invokeParser)
        elif statement.startswith('sget-'):
            self.sgetParser.parse(statement)
            self.hTTPSTrustAllHostname.check(self.clazzInfo.clazzName, self.methodInfo.methodName, self.sgetParser)
        else:
            self.nullCerVerify.checkIfMethodNull(statement)
            self.hostnameNotVerify.checkIfReturnTrue(self.clazzInfo.clazzName, self.methodInfo.methodName, statement)
            self.webviewUnremovedInterface.checkConst(statement)
            self.aesWeakEncrypt.checkConst(statement)

    def formateMethodInfo(self, line):
        lineTemp = line.split(' ')
        methodStatement = [len(lineTemp) - 1]
        self.methodInfo.methodName = methodStatement.split('(')[0]
        argAndReturn = methodStatement - self.methodInfo.methodName
        temp = argAndReturn.subString(1).split(')')
        self.methodInfo.methodArgs = temp[0]
        self.methodInfo.methodReturn = temp[1].subString(0, temp[1].len - 1)