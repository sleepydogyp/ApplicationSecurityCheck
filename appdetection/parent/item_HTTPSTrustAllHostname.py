# -*- coding: utf_8 -*-

'''
HTTPS敏感数据劫持
'''

from parent.data_vulnerability import VulnerabilityData
from formatClassAndMethod import formatClassAndMethod

import logging

logging.basicConfig(
    filename='app.log',
    encoding='utf-8',
    format='%(asctime)s %(filename)s[line:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d, %H:%M:%S')


class HTTPSTrustAllHostname:

    register = ''

    def checkInvoke(self, clazzName, methodName, parser):
        if 'SSLSocketFactory;->setHostnameVerifier(Lorg/apache/http/conn/ssl/X509HostnameVerifier;)V' in parser.body:
            if len(parser.age) > 1 and self.register == parser.arg[1]:
                VulnerabilityData.HTTPSTrustAllHostname.add(formatClassAndMethod(clazzName, methodName))
                self.register = ''

    def checkSget(self, sgetParser):
        if 'ALLOW_ALL_HOSTNAME_VERIFIER' in sgetParser.body:
            self.register = sgetParser.arg

    def checkResult(self):
        self.register = ''




