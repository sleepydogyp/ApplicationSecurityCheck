# -*- coding: utf_8 -*-

'''
HTTPS敏感数据劫持
'''

from data_vulnerability import VulnerabilityData
from formatClassAndMethod import formatClassAndMethod

import logging

logging.basicConfig(
    filename='app.log',
    encoding='utf-8',
    format='%(asctime)s %(filename)s[line:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d, %H:%M:%S')


class HTTPSHostnameVerify:

    register = ''

    def check(self, clazzName, methodName, parser):
        if parser.operation == 'invoke-virtual':
            if 'SSLSocketFactory;->setHostnameVerifier(Lorg/apache/http/conn/ssl/X509HostnameVerifier;)V' in parser.body:
                if len(parser.age) > 1 and self.register == parser.arg[1]:
                    VulnerabilityData.HTTPSHostnameVerify.add(formatClassAndMethod(clazzName, methodName))
                    self.register = ''
        elif parser.operation == 'sget-object':
            if 'ALLOW_ALL_HOSTNAME_VERIFIER' in parser.body:
                self.register = parser.arg
        elif '.end method' in parser.body:
            self.register = ''

        




