# -*- coding: utf_8 -*-

'''
parse smali file 
'''

import logging


from item_contentProviderDirTraversal import ContentProviderDirTraversal
from item_WebviewIgnoreSSLVerify import WebviewIgnoreSSLVerify
from item_HTTPSHostnameVerify import HTTPSHostnameVerify

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
    methodSet = set()


class DetectItemsEntry:

    clazzInfo = ClazzInfo()
    methodInfo = MethodInfo()

    invokeParser = InvokeParser()
    sgetParser = SgetParser()
    endMethodParser = EndMethodParser()

    contentProviderDirTraversal = ContentProviderDirTraversal()
    webviewIgnoreSSLVerify = WebviewIgnoreSSLVerify()
    hTTPSHostnameVerify = HTTPSHostnameVerify()

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
            elif line.startswith('.method'):
                isMethod = True
                self.formateMethodInfo(line)
                # Content Provider目录遍历漏洞
                if self.currentMethod == 'openFile':
                    self.contentProviderDirTraversal.check(self.clazzInfo.clazzName, self.methodInfo.methodName, self.methodInfo.methodArgs, self.methodInfo.methodReturn)
                continue
            elif line == '.end method':
                isMethod = False
                self.currentMethod = ''
            elif isMethod:
                self.detect(line)

    def detect(self, statement):
        # invoke语句, invoke-direct, invoke-virtual, invoke-static
        if statement.startswith('invoke-'):
            self.invokeParser.parse(statement)
            # WebView忽略SSL证书验证错误漏洞
            self.webviewIgnoreSSLVerify.check(self.clazzInfo, self.methodInfo, self.invokeParser)
            # HTTPS敏感数据劫持
            self.hTTPSHostnameVerify.check(self.clazzInfo.clazzName, self.methodInfo.methodName, self.invokeParser)
        elif statement.startswith('sget-'):
            self.sgetParser.parse(statement)
            self.hTTPSHostnameVerify.check(self.clazzInfo.clazzName, self.methodInfo.methodName, self.sgetParser)
        elif statement.startswith('.end method'):
            self.endMethodParser.parse(statement)
            self.hTTPSHostnameVerify.check(self.clazzInfo.clazzName, self.methodInfo.methodName, self.endMethodParser)

    def formateMethodInfo(self, line):
        lineTemp = line.split(' ')
        methodStatement = [len(lineTemp) - 1]
        self.methodInfo.methodName = methodStatement.split('(')[0]
        argAndReturn = methodStatement - self.methodInfo.methodName
        temp = argAndReturn.subString(1).split(')')
        self.methodInfo.methodArgs = temp[0]
        self.methodInfo.methodReturn = temp[1].subString(0, temp[1].len -1)