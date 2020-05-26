# -*- coding: utf_8 -*-

import logging

from appdetection.parent.common.commands import decompileApk
from appdetection.parent.appoverview.overviewController import overviewManager
from appdetection.parent.smaliparser.smali_parse_entry import smaliFilesEntry


logging.basicConfig(
    filename='appdetect.log',
    level=logging.DEBUG,
    format='%(asctime)s %(filename)s[line:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d, %H:%M:%S')


class DetectEntry:

    def __init__(self, path):
        self.path = path

    def detetctManager(path):
        if (path.endwith('.apk')):
    
            decompileApk(path)
            dirPath = path.split('.apk')[0]

            # 1. overview
            overView = overviewManager(dirPath)
            logging.info('overViewInfo: ' + overView)
            # 2. vulnerability scan of smali
            smaliFilesEntry(dirPath)

            # TODO: 1.analysis in method;
            # TODO: 2.analysis between methods;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  