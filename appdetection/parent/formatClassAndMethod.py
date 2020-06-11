# -*- coding: utf_8 -*-

'''
检测结果语句格式化
'''


def formatClassAndMethod(className, methodName):
    className = className[1:].replace('/', '.')
    methodName = methodName.split('(')[0]
    formatedResult = className + ' : ' + methodName
    return formatedResult
    
    