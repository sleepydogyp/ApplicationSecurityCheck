# -*- coding: utf_8 -*-

'''
HTTPS敏感数据劫持
'''

from parent.data_vulnerability import VulnerabilityData
from formatClassAndMethod import formatClassAndMethod


class HTTPSTrustAllHostname:

    def __init__(self, vulnerabilityData):
        self.vulnerabilityData = vulnerabilityData

    register = ''

    def checkInvoke(self, clazzName, methodName, parser):
        if 'SSLSocketFactory;->setHostnameVerifier(Lorg/apache/http/conn/ssl/X509HostnameVerifier;)V' in parser.body:
            if len(parser.arg) > 1 and self.register == parser.arg[1]:
                self.vulnerabilityData.HTTPSTrustAllHostname.add(formatClassAndMethod(clazzName, methodName))
                self.register = ''

    def checkSget(self, sgetParser):
        if 'ALLOW_ALL_HOSTNAME_VERIFIER' in sgetParser.body:
            self.register = sgetParser.arg

    def checkResult(self):
        self.register = ''




