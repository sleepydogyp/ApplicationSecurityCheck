# -*- coding: utf_8 -*-


class SgetParser():
    operation = ''
    arg = ''
    body = ''

    def parse(self, statement):
        temp = statement.split(' ')
        self.operation = temp[0]
        self.body = temp[len(temp) - 1]
        self.arg = temp[1].split(',')[0]


class InvokeParser():
    operation = ''
    arg = list()
    body = ''

    def parse(self, statement):
        temp = statement.split(' ')
        self.operation = temp[0]
        self.body = temp[len(temp) - 1]
        argsStr = statement.split('{')[1].split('}')[0]
        argsTemp = argsStr.split(' ')
        argsLen = len(argsTemp)
        if argsLen == 1:
            self.arg.append(argsTemp[0])
        elif argsLen > 1:
            i = 0
            while i < argsLen:
                self.arg.append(argsTemp[i].split(',')[0])
                i += 1


class EndMethodParser():
    body = ''

    def parse(self, statement):
        self.body = statement


class ConstParser():
    operation = ''
    arg = ''
    value = ''

    def parse(self, statement):
        temp = statement.split(' ')
        if len(temp) > 2:
            self.operation = temp[0]
            self.arg = temp[1]
            self.value = temp[2]


class ReturnParser():
    operation = ''
    value = ''

    def parse(self, statement):
        if 'return-void' in statement:
            self.operation = statement
        else:
            temp = statement.split(' ')
            if len(temp) > 1:
                self.operation = temp[0]
                self.value = temp[1]

