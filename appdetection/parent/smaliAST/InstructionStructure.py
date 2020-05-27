# -*- coding: utf_8 -*-


class Instruction:
    def __init__(self, instructionType, content):
        self.type = instructionType
        self.content = content


# invoke-direct invoke-static/range
class invoke:
    def __init__(self, instruction, params, operation):
        self.instruction = instruction
        self.params = params
        self.operation = operation


# new-instance
class newInstance:
    def __init__(self, instruction, dst, clazz):
        self.instruction = instruction
        self.dst = dst
        self.clazz = clazz


# iput-object iget-object
class memberVariableOperation:
    def __init__(self, instruction, dst, this, variable):
        self.instruction = instruction
        self.dst = dst
        self.this = this
        self.variable = variable


# move-to-result
class moveToResult:
    def __init__(self, instruction, dst):
        self.instruction = instruction
        self.dst = dst