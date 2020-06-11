# -*- coding: utf_8 -*-

'''
敏感数据加密存储
'''

from parent.data_vulnerability import VulnerabilityData
from formatClassAndMethod import formatClassAndMethod

from statementParser import ConstParser, InvokeParser


class SensiDataStorage:

    def __init__(self, vulnerabilityData):
        self.vulnerabilityData = vulnerabilityData

    pass