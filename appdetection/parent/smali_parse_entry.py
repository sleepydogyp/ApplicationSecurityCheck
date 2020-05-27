# -*- coding: utf_8 -*-

import logging
import os

from detectItemsEntry import SmaliParser

logging.basicConfig(
    filename='app.log',
    level=logging.DEBUG,
    format='%(asctime)s %(filename)s[line:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d, %H:%M:%S')

# store results of parsed smali files
smaliTrees = set()


def smaliFilesEntry(dirPath):
    for root, dirs, files in os.walk(dirPath):
        for dir in dirs:
            if (dir.startswith('smali')):
                smaliDir = dirPath + '/' + dir
                for root, dirs, files in os.walk(smaliDir):
                    for file in files:
                        thisFilePath = os.path.join(root, file)
                        thisFilePath = thisFilePath.replace('\\', '/')
                        if '/android' not in thisFilePath:
                            # logging.info('dir: ' + dir + '/' + file)
                            smaliLines = readSmaliFileByLine(thisFilePath)
                            smaliParser = SmaliParser()
                            smaliParser.parseSmaliFile(smaliLines)
            else:
                continue


# 按行读取smali文件
def readSmaliFileByLine(filePath):
    smaliLines = list()
    file = open(filePath)
    while 1:
        lines = file.readlines(10000)
        if not lines:
            break
        for line in lines:
            smaliLines.append(line)
    file.close()
    return smaliLines


def main():
    dirPath = "F:/testApks/58tongcheng"
    smaliFilesEntry(dirPath)


if __name__ == "__main__":
    main()
