# -*- coding: utf_8 -*-

'''
unzip目录遍历漏洞
'''

from parent.parent.data_vulnerability import VulnerabilityData
from formatClassAndMethod import formatClassAndMethod

from statementParser import ConstParser, InvokeParser


class UnzipDirTraverse:

    constMap = dict()
    isGetName = False

    def checkInvoke(self, clazzName, methodName, invokeParser):
        if 'Ljava/util/zip/ZipEntry;->getName()Ljava/lang/String;' in invokeParser.body:
            self.isGetName = True
        elif 'Ljava/io/File;->getCanonicalPath()Ljava/lang/String;' in invokeParser.body:
            self.isGetName = False
        elif 'Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z' in invokeParser:
            if len(invokeParser.arg) > 1 and invokeParser.arg[0] in self.constMap.values() and '../' in self.constMap[invokeParser.arg[0]]:
                self.isGetName = False
        elif 'Ljava/util/zip/ZipInputStream;->read([BII)I' in invokeParser:
            if self.isGetName:
                VulnerabilityData.unzipDirTraverse.add(formatClassAndMethod(clazzName, methodName))

    def checkConst(self, statement):
        if statement.startswith('const'):
            constParser = ConstParser()
            constParser.parse(statement)
            if constParser.arg in self.constMap:
                self.constMap[constParser.arg] = constParser.value
            else:
                self.constMap[constParser.arg] = self[constParser.value]

    def checkResult(self):
        self.constMap.clear()
        self.isGetName = False
