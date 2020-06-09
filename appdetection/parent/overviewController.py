# -*- coding: utf_8 -*-

import logging

from parent.manifest_parser import parseManifest
from commands import getBaseInfo, getCertInfos
from parent.data_appBase import AppBaseData

logging.basicConfig(
    filename='app.log',
    level=logging.DEBUG,
    format='%(asctime)s %(filename)s[line:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d, %H:%M:%S')


def overviewManager(dirPath):
    # 1.parse AndroidManifest
    parseManifestInfos(dirPath)

    # 2. get appName , icon and version
    parseBaseInfos(dirPath)

    # 3. is debug cer or release cer
    AppBaseData.isDebugCert = parseCert(dirPath)


def parseManifestInfos(dirPath):
    manifestFilePath = dirPath + '/AndroidManifest.xml'

    # TODO: detect failed!
    parseManifest(manifestFilePath)


# 应用名、版本号、图标
def parseBaseInfos(dirPath):
    getBaseInfo(dirPath + '.apk')


# 是否为deubg证书
def parseCert(dirPath):
    return getCertInfos(dirPath + '.apk')
