# -*- coding: utf_8 -*-


'''
解析smali文件的class信息，和method声明信息
'''


class MethodInfo:
    methodName = ''
    methodArgs = ''
    methodReturn = ''

    def formateMethodInfo(self, line):
        lineTemp = line.split(' ')
        methodStatement = lineTemp[len(lineTemp) - 1]
        self.methodName = methodStatement.split('(')[0]
        argAndReturn = methodStatement.split('(')[1]
        if argAndReturn.startswith(')'):
            self.methodArgs = ''
            self.methodReturn = argAndReturn[1:].replace('\n', '')
        else:
            temp = argAndReturn.split(')')
            self.methodArgs = temp[0]
            self.methodReturn = temp[1].replace('\n', '')


class ClazzInfo:
    clazzName = ''
    superClazz = ''
    implements = ''
    methodSet = set()