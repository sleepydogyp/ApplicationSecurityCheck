# -*- coding: utf_8 -*-

'''
parse smali file 
'''

import logging


from item_contentProviderDirTraversal import ContentProviderDirTraversal

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
            if line == '\n':
                continue
            if line.startswith('.class'):
                temp = line.split(' ')
                self.className = temp[len(temp) - 1].split(';')[0]
                logging.info('className: ' + self.className)
            elif line.startswith('.method'):
                isMethod = True
                temp = line.split(' ')
                self.currentMethod = temp[len(temp) - 1].split('(')[0]
                logging.info('currentMethod: ' + self.currentMethod)
                # Content Provider目录遍历漏洞
                if self.currentMethod == 'openFile':
                    ContentProviderDirTraversal().check(self.className, self.currentMethod, temp[len(temp) - 1])
                continue
            elif line == '.end method':
                isMethod = False
                self.currentMethod = ''
            elif isMethod:
                self.detect(line)

    def detect(self, statement):
        # invoke语句, invoke-direct, invoke-virtual, invoke-static
        if statement.startswith('invoke-'):
            temp = statement.split(' ')
            invokeStatement = temp[len(temp) - 1]
            logging.info(invokeStatement)
        