# -*- coding: utf_8 -*-

'''
HTTPS证书空校验
'''
from parent.data_vulnerability import VulnerabilityData
from formatClassAndMethod import formatClassAndMethod
from detecctItemsEntry import ClazzInfo


class NullCerVerify:

    isCerVerifyMethod = False
    isLineNum = False
    isMethodNull = False

    # .method
    def checkMethod(self, clazzInfo):
        if 'Ljavax/net/ssl/X509TrustManager;' in clazzInfo.implements:
            self.isCerVerifyMethod = True

    def checkIfMethodNull(self, statement):
        if self.isCerVerifyMethod:
            if '.line' in statement:
                self.isLineNum = True
            elif self.isLineNum and 'return' in statement:
                self.isMethodNull = True
            else:
                self.isLineNum = False
        
    # .end method
    def checkResult(self, clazzInfo, methodName):
        if self.isMethodNull and self.isLineNum:
            VulnerabilityData.nullCerVerify.add(formatClassAndMethod(clazzInfo.clazzName, methodName))
        self.isLineNum = False
        self.isMethodNull = False
        self.isCerVerifyMethod = False
