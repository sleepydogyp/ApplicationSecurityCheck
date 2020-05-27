# -*- coding: utf_8 -*-

from abc import ABCMeta, abstractmethod


class Parser(metaclass=ABCMeta):
    @abstractmethod
    def parse(self, statement):
        pass


class SgetParser(Parser):
    operation = ''
    arg = ''
    body = ''

    def parse(self, statement):
        temp = statement.split(' ')
        self.operation = temp[0]
        self.body = temp[len(temp) - 1]
        self.arg = temp[1].split(',')[0]


class InvokeParser(Parser):
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


class EndMethodParser(Parser):
    body = ''

    def parse(self, statement):
        self.body = statement         