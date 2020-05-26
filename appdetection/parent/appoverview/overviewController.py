# -*- coding: utf_8 -*-

import logging

from appdetection.parent.appoverview.manifest_parser import parseManifest
from appdetection.parent.common.commands import getBaseInfo, getCertInfos

logging.basicConfig(
    filename='appdetect.log',
    level=logging.DEBUG,
    format='%(asctime)s %(filename)s[line:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d, %H:%M:%S')


def overviewManager(dirPath):
    overView = {}
    # 1.parse AndroidManifest
    overView['manifestInfos'] = parseManifestInfos(dirPath)

    # 2. get appName , icon and version
    overView['baseInfo'] = parseBaseInfos(dirPath)

    # 3. is debug cer or release cer
    overView['isDebugCert'] = parseCert(dirPath)
    return overView


def parseManifestInfos(dirPath):
    manifestFilePath = dirPath + '/AndroidManifest.xml'

    # TODO: detect failed!
    return parseManifest(manifestFilePath)


# 应用名、版本号、图标
def parseBaseInfos(dirPath):
    return getBaseInfo(dirPath + '.apk')


# 是否为deubg证书
def parseCert(dirPath):
    return getCertInfos(dirPath + '.apk')
