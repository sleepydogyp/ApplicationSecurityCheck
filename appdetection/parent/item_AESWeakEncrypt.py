# -*- coding: utf_8 -*-

'''
AES/DES弱加密
'''

from data_vulnerability import VulnerabilityData
from formatClassAndMethod import formatClassAndMethod

from statementParser import ConstParser, InvokeParser


class AESWeakEncrypt:

    register = ''

    def checkInvoke(self, clazzName, methodName, invokeParser):
        if not self.register == '' and 'Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;' in invokeParser.body and self.register == invokeParser.arg[0]:
            VulnerabilityData.aesWeakEncrypt.add(formatClassAndMethod(clazzName, methodName))
            self.register = ''
    
    def checkConst(self, statement):
        if statement.startswith('const-string'):
            constParser = ConstParser()
            constParser.parse(statement)
            if constParser.value.startswith('AES') or constParser.value.startswith('DES'):
                if 'ECB/NoPadding' in constParser.value or 'OFB/Nopadding' in constParser.value:
                    self.register = constParser.arg