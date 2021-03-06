# -*- coding: utf_8 -*-

import os
import subprocess
import zipfile

from data_appBase import AppBaseData

'''
需要执行命令的方法
'''


# 反编译apk
def decompileApk(apkPath, dirPath):
    os.system('apktool -f d ' + apkPath + ' -o ' + dirPath)


# 应用名、版本号、图标
def parseBaseInfos(apkPath, appBaseData):
    cmd = "aapt dump badging %s" % (apkPath)
    # outputLines = os.popen(cmd).readlines()
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    for line in iter(p.stdout.readline, b''):
    # for line in outputLines:
        line = line.strip().decode('utf-8')
        if line.startswith('package: '):
            subLine = line[9:]
            for attrib in subLine.split(' '):
                if attrib.startswith('versionName'):
                    versionName = attrib.split('\'')[1]
                    appBaseData.versionName = versionName
                    break
        elif line.startswith('application: '):
            attribs = line.split(' ')
            for attrib in attribs:
                if attrib.startswith('label'):
                    appName = attrib.split('\'')[1]
                    appBaseData.appName = appName
                elif attrib.startswith('icon'):
                    appIcon = attrib.split('\'')[1]
                    appBaseData.appIcon = appIcon


# 证书信息：是否为debug证书
def parseCert(dirPath, appBaseData):
    zdir = zipfile.ZipFile(dirPath + '.apk', 'r')
    zdir.extractall(dirPath + '_upzip')
    # zdir.extract('/META-INF', apkPath)
    cmd = 'keytool -printcert -file ' + dirPath + '_unzip/META-INF/CERT.RSA'
    # cmd = 'keytool -printcert -file ' + apkPath + '/META-INF/CERT.RSA'
    outputLines = os.popen(cmd).readlines()
    for line in outputLines:
        if line.startswith('所有者') and line.endswith('Debug'):
            appBaseData.isDebugCert = True
