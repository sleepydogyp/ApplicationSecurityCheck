# -*- coding: utf_8 -*-

import logging
import shutil

from commands import decompileApk
from overviewController import overviewManager
from smali_parse_entry import smaliFilesEntry

from data_appBase import AppBaseData
from data_vulnerability import VulnerabilityData


logging.basicConfig(
    filename='app.log',
    level=logging.DEBUG,
    format='%(asctime)s %(filename)s[line:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d, %H:%M:%S')


class DetectEntry:

    def __init__(self, path):
        self.path = path

    def detetctManager(self):
        if (self.path.endswith('.apk')):
            appBaseData = AppBaseData()
            vulnerabilityData = VulnerabilityData()

            # 1. decompile apk
            dirPath = self.path.split('.apk')[0]
            decompileApk(self.path, dirPath)

            # 2. overview
            overView = overviewManager(dirPath, appBaseData)

            # 3. vulnerability scan of smali
            smaliFilesEntry(dirPath, vulnerabilityData)

            # TODO: analysis between methods; 
            # 4. get data
            appBaseDataDict = appBaseData.outputAppBaseData()
            vulnerabilityDataDict = vulnerabilityData.outputVulnerabilityData()
            logging.info('appBaseInfo: ' + str(appBaseDataDict))
            logging.info('vulnerabilityData: ' + str(vulnerabilityDataDict))

            # 5. delete temp dir
            shutil.rmtree(dirPath)
            shutil.rmtree(dirPath + '_upzip')

            


def main():
    path = "F:/testApks/zhoumoqunaer.apk"
    detectEntry = DetectEntry(path)
    detectEntry.detetctManager()
    
if __name__ == "__main__":
    main()                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 