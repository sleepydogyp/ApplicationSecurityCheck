# -*- coding: utf_8 -*-

'''
HTTPS 域名未验证
'''

from data_vulnerability import VulnerabilityData
from formatClassAndMethod import formatClassAndMethod

from statementParser import ConstParser, ReturnParser


class HostnameNotVerify:

    isHostNameVerifyMethod = False
    isConst = False
    
    constParser = ConstParser()

    def checkMethod(self, clazzInfo):
        if 'Ljavax/net/ssl/HostnameVerifier;' in clazzInfo.implements:
            self.isHostNameVerifyMethod = True

    def checkIfReturnTrue(self, clazzName, methodName, statement):
        if self.isHostNameVerifyMethod:
            if statement.startswith('const'):
                self.constParser.parse(statement)
                self.isConst = True
            elif statement.startswith('return'):
                if self.isConst:
                    returnParser = ReturnParser()
                    returnParser.parse(statement)
                    if returnParser.value == self.constParser.arg and self.constParser.value == '0x1':
                        VulnerabilityData.HostnameNotVerify.add(formatClassAndMethod(clazzName, methodName))
                        self.isConst = False
                        self.isHostNameVerifyMethod = False
                        self.constParser = ConstParser()
            else:
                self.isConst = False
                


