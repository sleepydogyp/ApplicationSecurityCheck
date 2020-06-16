# -*- coding: utf_8 -*-

import logging

from manifest_parser import parseManifest
from commands import parseBaseInfos, parseCert
from data_appBase import AppBaseData

logging.basicConfig(
    filename='app.log',
    level=logging.DEBUG,
    format='%(asctime)s %(filename)s[line:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d, %H:%M:%S')


def overviewManager(dirPath, appBaseData):
    # 1.parse AndroidManifest
    # TODO: detect failed!
    parseManifest(dirPath+ '/AndroidManifest.xml', appBaseData)

    # 2. get appName , icon and version
    parseBaseInfos(dirPath + '.apk', appBaseData)

    # 3. is debug cer or release cer
    parseCert(dirPath, appBaseData)
