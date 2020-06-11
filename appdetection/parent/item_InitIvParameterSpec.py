# -*- coding: utf_8 -*-

'''
初始化IvParameterSpec错误
'''

import re

from parent.data_vulnerability import VulnerabilityData
from formatClassAndMethod import formatClassAndMethod

from statementParser import ConstParser, InvokeParser


class InitIvparameterSpec:

    def __init__(self, vulnerabilityData):
        self.vulnerabilityData = vulnerabilityData

    constSet = set()
    getBytearg = ''

    def checkInvoke(self, clazzName, methodName, invokeParser):
        if 'Ljava/lang/String;->getBytes()[B' in invokeParser.body:
            if len(invokeParser.arg) > 0 and invokeParser.arg[0] in self.constSet:
                self.getBytearg = invokeParser.arg[0]
            elif 'Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V' in invokeParser.body:
                if self.getBytearg != '' and len(invokeParser.arg) > 1 and invokeParser.arg[1] == self.getBytearg:
                    self.vulnerabilityData.initIvparameterSpec.add(formatClassAndMethod(clazzName, methodName))

    def checkConst(self, statement):
        if statement.startswith('const'):
            constParser = ConstParser()
            constParser.parse(statement)
            matchObj = re.search('[0-9]+', constParser.value)
            if matchObj:
                self.constSet.add(constParser.arg)

    def checkResult(self):
        self.constSet.clear()
        self.getBytearg = ''
