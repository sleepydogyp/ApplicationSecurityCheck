# -*- coding: utf_8 -*-


class SmaliClazz:
    def __init__(self):
        self.clazz = ""
        self.superClazz = ""
        self.fields = set()


class Field:
    def __init__(self, modifiers, name, value, fieldType, attribute):
        self.modifiers = modifiers
        self.name = name
        self.value = value
        self.fieldType = fieldType
        self.attribute = attribute


class Annotation:
    def __init__(self, modifier, annotationType, value):
        self.modifier = modifier
        self.type = annotationType
        self.value = value


class Method:
    def __init__(self, modifiers, methodName, params, returnType, sentences):
        self.modifiers = modifiers
        self.methodName = methodName
        self.params = params
        self.returnType = returnType
        self.sentences = sentences


