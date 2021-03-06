# -*- coding: utf_8 -*-

'''
HTTPS 域名未验证
'''

from parent.data_vulnerability import VulnerabilityData
from formatClassAndMethod import formatClassAndMethod

from statementParser import ConstParser, ReturnParser


class HostnameNotVerify:

    def __init__(self, vulnerabilityData):
        self.vulnerabilityData = vulnerabilityData

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
                    if returnParser.value == self.constParser.arg and '0x1' in self.constParser.value:
                        self.vulnerabilityData.hostnameNotVerify.add(formatClassAndMethod(clazzName, methodName))
                        self.isConst = False
                        self.isHostNameVerifyMethod = False
                        self.constParser = ConstParser()
            else:
                self.isConst = False
                
    def checkResult(self):
        self.isConst = False
        self.isHostNameVerifyMethod = False
        self.constParser = ConstParser()



