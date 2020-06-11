# -*- coding: utf_8 -*-

'''
parse smali file 
'''

import logging
import sys
sys.path.append("H:\\MyGithub\\ApplicationSecurityCheck\\appdetection\\")


from item_WebviewIgnoreSSLVerify import WebviewIgnoreSSLVerify
from item_HTTPSTrustAllHostname import HTTPSTrustAllHostname
from item_NullCerVerify import NullCerVerify
from item_HostnameNotVerify import HostnameNotVerify
from parent.item_WebviewUnremovedInterface import WebViewUnremovedInterface
from item_AESWeakEncrypt import AESWeakEncrypt
from item_webViewSavePasswordAndFileAccess import WebViewSavePasswordAndFileAccess
from item_SensiDataStorage import SensiDataStorage
from item_RSAWeakEncrypt import RSAWeakEncrypt
from item_unzipDirTraverse import UnzipDirTraverse
from item_DynamicLoadDex import DynamicLoadDex
from item_ContentProviderDirtraverse import ContentProviderDirTraverse
from item_InitIvParameterSpec import InitIvparameterSpec
from item_LocalDOS import LocalDOS
from item_DynamicBroadcast import DynamicBroadcast

from statementParser import InvokeParser, SgetParser, EndMethodParser
from clazzAndMethodInfo import ClazzInfo, MethodInfo


logging.basicConfig(
    filename='app.log',
    level=logging.DEBUG,
    format='%(asctime)s %(filename)s[line:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d, %H:%M:%S')


class DetectItemsEntry:


    def __init__(self, vulnerabilityData):
        self.vulnerabilityData = vulnerabilityData

        self.clazzInfo = ClazzInfo()
        self.methodInfo = MethodInfo()

        self.invokeParser = InvokeParser()
        self.sgetParser = SgetParser()
        self.endMethodParser = EndMethodParser()

        self.webviewIgnoreSSLVerify = WebviewIgnoreSSLVerify(vulnerabilityData)
        self.hTTPSTrustAllHostname = HTTPSTrustAllHostname(vulnerabilityData)
        self.nullCerVerify = NullCerVerify(vulnerabilityData)
        self.hostnameNotVerify = HostnameNotVerify(vulnerabilityData)
        self.webviewUnremovedInterface = WebViewUnremovedInterface(vulnerabilityData)
        self.aesWeakEncrypt = AESWeakEncrypt(vulnerabilityData)
        self.webViewSavePasswordAndFileAccess = WebViewSavePasswordAndFileAccess(vulnerabilityData)
        self.sensiDataStorage = SensiDataStorage(vulnerabilityData)
        self.rsaWeakEncrypt = RSAWeakEncrypt(vulnerabilityData)
        self.unzipDirTraverse = UnzipDirTraverse(vulnerabilityData)
        self.dynamicLoadDex = DynamicLoadDex(vulnerabilityData)
        self.contentProviderDirTraverse = ContentProviderDirTraverse(vulnerabilityData)
        self.initIvParameterSpec = InitIvparameterSpec(vulnerabilityData)
        self.localDOS = LocalDOS(vulnerabilityData)
        self.dynamicBroadcast = DynamicBroadcast(vulnerabilityData)

    def parseSmaliFile(self, smaliLines):
        isMethod = False
        for line in smaliLines:
            if line == '\n':
                continue
            if line.startswith('.class'):
                self.clazzInfo.implements = ''
                temp = line.split(' ')
                self.clazzInfo.clazzName = temp[len(temp) - 1].split(';')[0]
                logging.info('className: ' + self.clazzInfo.clazzName)
            elif line.startswith('.super'):
                self.clazzInfo.superClazz = line.replace('.super ', '')
            elif line.startswith('.implements '):
                self.clazzInfo.implements = line.split(' ')[1]
            elif line.startswith('.method'):
                isMethod = True
                self.methodInfo.formateMethodInfo(line)
                # HTTPS证书空校验
                if self.methodInfo.methodName == 'checkServerTrusted' or self.methodInfo.methodName == 'checkClientTrusted':
                    self.nullCerVerify.checkMethod(self.clazzInfo)
                # HTTPS 域名未验证
                elif self.methodInfo.methodName == 'verify' and 'Ljavax/net/ssl/SSLSession;' in self.methodInfo.methodArgs:
                    self.hostnameNotVerify.checkMethod(self.clazzInfo)
                
                continue
            elif '.end method' in line:
                isMethod = False
                self.endMethodParser.parse(line)
                self.hTTPSTrustAllHostname.checkResult()
                self.nullCerVerify.checkResult(self.clazzInfo, self.methodInfo.methodName)
                self.hostnameNotVerify.checkResult()
                self.webviewUnremovedInterface.checkResult(self.clazzInfo.clazzName, self.methodInfo.methodName)
                self.aesWeakEncrypt.checkResult()
                self.webViewSavePasswordAndFileAccess.checkResult(self.clazzInfo.clazzName, self.methodInfo.methodName)
                self.rsaWeakEncrypt.checkResult()
                self.unzipDirTraverse.checkResult()
                self.dynamicLoadDex.checkResult()
                self.initIvParameterSpec.checkResult()
                self.dynamicBroadcast.checkResult()
                self.methodInfo = MethodInfo()  # method结束，重新初始化MethodInfo
            elif isMethod:  # 方法内
                self.detect(line)

    def detect(self, statement):
        if statement.startswith('    .locals') or statement.startswith('    .line'):
            return
        # invoke语句, invoke-direct, invoke-virtual, invoke-static
        elif statement.startswith('    invoke-'):
            self.invokeParser.parse(statement)
            # WebView忽略SSL证书验证错误漏洞
            self.webviewIgnoreSSLVerify.checkInvoke(self.clazzInfo, self.methodInfo, self.invokeParser)
            # HTTPS敏感数据劫持
            self.hTTPSTrustAllHostname.checkInvoke(self.clazzInfo.clazzName, self.methodInfo.methodName, self.invokeParser)
            # 未移除有风险的WebView接口
            self.webviewUnremovedInterface.checkInvoke(self.invokeParser)
            # AES/DES弱加密
            self.aesWeakEncrypt.checkInvoke(self.clazzInfo.clazzName, self.methodInfo.methodName, self.invokeParser)
            # WebView明文存储密码，WebViewFile域绕过
            self.webViewSavePasswordAndFileAccess.checkInvoke(self.invokeParser)
            # TODO:敏感数据加密存储
            # self.sensiDataStorage.checkInvoke(self.invokeParser)
            # RSA弱加密
            self.rsaWeakEncrypt.checkInvoke(self.clazzInfo.clazzName, self.methodInfo.methodName, self.invokeParser)
            # unzip目录遍历漏洞
            self.unzipDirTraverse.checkInvoke(self.clazzInfo.clazzName, self.methodInfo.methodName, self.invokeParser)
            # 动态加载DEX文件
            self.dynamicLoadDex.checkInvoke(self.clazzInfo.clazzName, self.methodInfo.methodName, self.invokeParser)
            # ContentProvider目录遍历漏洞
            self.contentProviderDirTraverse.checkInvoke(self.clazzInfo.clazzName, self.methodInfo.methodName, self.invokeParser)
            # 初始化IvParameterSpec错误
            self.initIvParameterSpec.checkInvoke(self.clazzInfo.clazzName, self.methodInfo.methodName, self.invokeParser)
            # 本地拒绝服务攻击
            self.localDOS.checkInvoke(self.clazzInfo.clazzName, self.methodInfo.methodName, self.invokeParser)
            # 动态注册广播暴露风险
            self.dynamicBroadcast.checkInvoke(self.clazzInfo.clazzName, self.methodInfo.methodName, self.invokeParser)
        elif statement.startswith('    sget-'):
            self.sgetParser.parse(statement)
            self.hTTPSTrustAllHostname.checkSget(self.sgetParser)
        else:
            self.nullCerVerify.checkIfMethodNull(statement)
            self.hostnameNotVerify.checkIfReturnTrue(self.clazzInfo.clazzName, self.methodInfo.methodName, statement)
            self.webviewUnremovedInterface.checkConst(statement)
            self.aesWeakEncrypt.checkConst(statement)
            self.webViewSavePasswordAndFileAccess.checkConst(statement)
            self.rsaWeakEncrypt.checkConst(statement)
            self.unzipDirTraverse.checkConst(statement)
            self.dynamicLoadDex.checkConst(statement)
            self.initIvParameterSpec.checkConst(statement)
            self.dynamicBroadcast.checkConst(statement)

