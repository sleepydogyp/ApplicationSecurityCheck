# -*- coding: utf_8 -*-

'''
parse smali file 
'''
import logging

import appdetection.parent.vulnerabilityscan.contentProviderDirTraversal \
    as ContentProviderDirTraversal

logging.basicConfig(
    filename='app.log',
    level=logging.DEBUG,
    format='%(asctime)s %(filename)s[line:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d, %H:%M:%S')


class SmaliParser:

    className = ''
    currentMethod = ''

    def parseSmaliFile(self, smaliLines):
        isMethod = False
        for line in smaliLines:
            logging.info('line: ' + line)
            if line.startswith('.class'):
                temp = line.split(' ')
                self.className = temp[len(temp) - 1].split(';')[0]
                logging.info('className: ' + self.className)
            elif line.startswith('.method'):
                temp = line.split(' ')
                self.currentMethod = temp[len(temp) - 1].split('(')[0]
                logging.info('currentMethod: ' + self.currentMethod)
                isMethod = True
                continue
            elif line == '.end method':
                isMethod = False
                self.currentMethod = ''
            elif isMethod:
                self.detect(self, line)

    def detect(self, statement):
        # Content Provider目录遍历漏洞
        ContentProviderDirTraversal().check(self.className, self.currentMethod, statement)
        