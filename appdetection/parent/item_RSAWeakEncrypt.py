# -*- coding: utf_8 -*-

'''
RSA弱加密
'''

from parent.data_vulnerability import VulnerabilityData
from formatClassAndMethod import formatClassAndMethod

from statementParser import ConstParser, InvokeParser


class RSAWeakEncrypt:

    isGetInstance = False
    constMap = dict()
    isSafePadding = True
    isSafeLength = False

    def checkInvoke(self, clazzName, methodName, invokeParser):
        if 'Ljava/security/KeyPairGenerator;->getInstance(Ljava/lang/String;' in invokeParser.body:
            self.isGetInstance = True
        elif 'Landroid/security/keystore/KeyGenParameterSpec$Builder;->setEncryptionPaddings([Ljava/lang/String;' in invokeParser.body:
            if self.isGetInstance and len(invokeParser.arg) > 1 and invokeParser.arg[1] in self.constMap:
                if 'NoPadding' in self.argMaps[invokeParser.arg[1]]:
                    self.isSafePadding = False
        elif 'Landroid/security/keystore/KeyGenParameterSpec$Builder;->setKeySize(I)' in invokeParser.body:
            if self.isGetInstance and len(invokeParser.arg) > 1 and invokeParser.arg[1] in self.constMap:
                if int(self.constMap[invokeParser.arg[1]], 16) >= 0x400:
                    self.isSafeLength = True
        elif 'Ljava/security/KeyPairGenerator;->generateKeyPair()Ljava/security/KeyPair;' in invokeParser.body:
            if self.isSafePadding and self.isSafeLength:
                VulnerabilityData.rsaWeakEncrypt.add(formatClassAndMethod(clazzName, methodName))

    def checkConst(self, statement):
        if statement.startswith('const'):
            constParser = ConstParser()
            constParser.parse(statement)
            if constParser.arg in self.constMap:
                self.constMap[constParser.arg] = constParser.value
            else:
                self.constMap[constParser.arg] = self[constParser.value]

    def checkResult(self):
        self.isGetInstance = False
        self.isSafePadding = True
        self.isSafeLength = False
        self.constMap.clear()