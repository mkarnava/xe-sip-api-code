# Copyright (c) 2021 Cisco and/or its affiliates.
#
# This software is licensed to you under the terms of the Cisco Sample
# Code License, Version 1.1 (the "License"). You may obtain a copy of the
# License at
#
#                https://developer.cisco.com/docs/licenses
#
# All use of the material herein must be in accordance with the terms of
# the License. All rights not expressly granted by the License are
# reserved. Unless required by applicable law or agreed to separately in
# writing, software distributed under the License is distributed on an "AS
# IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied.

import os
import shutil
import json
import xmltodict
import requests
import yaml
import base64 
from pathlib import Path
from datetime import date
from datetime import datetime
import tarfile


class Device:
    dev_id = 0
    ip = ""
    username = ""
    password = ""

    def __init__(self, device):
        try:
            self.dev_id = int(device["id"])
            self.ip = device["ip"]
            self.username = device["username"]
            self.password = device["password"]
            print("Device entry added")
        except Exception:
            print("Yaml file device entry is incomplete or invalid format")
            raise
        return

    def GetList(self):
        url = "https://" + self.ip + "/smartlic-service/list"
        hdr = {
            'FOXY-API-VERSION': "1",
            'Accept': "application/yang-data+json",
            'Content-Type': "application/yang-data+json",
            'Cache-Control': "no-cache"
        }

        response = requests.request("GET", url, auth=(self.username, self.password), headers=hdr, verify=False, timeout=5)
        json_resp = response.json()
        if('usage_list' in json_resp):
            print("Number of RUM reports: ", len(json_resp['usage_list']))

        print(response.json())
        return

    def GetAllRumReports(self):
        d = dict()
        url = "https://" + self.ip + "/smartlic-service/all-reports"
        hdr = {
            'Content-Type': "application/json",
        }
        response = requests.request("GET", url, auth=(self.username, self.password), headers=hdr, verify=False, timeout=5)
        resp_json = response.json()
        if('usage' not in resp_json):
            print("Device API Get All Reports returned empty")
            d['message'] = "empty"
            return d
        #print("Device API Get all report for ip: ", self.ip, " body: ", response.text)
        return resp_json


    def Import(self, str_import):
        url = "https://" + self.ip + "/smartlic-service/import"
        hdr = {
            'Content-Type': "application/json",
        }
        print("Import: received string len ", len(str_import))

        body = str_import.encode() 
        print("Import body type", type(body))

        my_json = body.decode('utf8').replace("'", '"')
        #print("my_json: ", my_json)

        response = requests.request("POST", url, auth=(self.username, self.password), headers=hdr, verify=False, data=my_json, timeout=5)
        print("Device API: Import API response code: ", response.status_code)
        return


    def CloseReports(self):
        url = "https://" + self.ip + "/smartlic-service/close-reports"
        hdr = {
            'Content-Type': "application/json",
        }
        body = {"test": ""}

        response = requests.request("POST", url, auth=(self.username, self.password), headers=hdr, verify=False, data=body, timeout=5)
        print("Device API: close RUM report response code: ", response.status_code)
        return


class CSSM:
    def __init__(self, cssm_access_type, cfg):
        try:
            if cssm_access_type == 'on':
                self.conn_type = 'online'
                self.client_id = cfg['api_keys']['client_id']
                self.client_secret = cfg['api_keys']['client_secret']
                self.username = cfg['api_keys']['username']
                self.password = cfg['api_keys']['password']
            else:
                self.conn_type = 'offline'
                self.client_id = ''
                self.client_secret = ''
                self.username = ''
                self.password = ''
                self.sa_domain = ''
                self.va_name = ''
                self.uuid = ''
        except Exception:
            print("Yaml file incomplete or invalid format")
            raise

        print("CSSM initialized with: ", self)

        return

    def GetAccessToken(self):
        d = dict()
        uri = "https://cloudsso.cisco.com/as/token.oauth2"
        body = {"client_id": self.client_id, "client_secret": self.client_secret,
                "username": self.username, "password": self.password,
                "grant_type": "password"}
        headers = {'Content-Type': "application/x-www-form-urlencoded"}
        print("Using uri: ", uri, "headers: ", headers, " body: ", body)
        response = requests.request("POST", uri, headers=headers, params=body)
        try:
            token_type = response.json()['token_type']
            print("CSSM API response: ", response.json())
            self.access_token = response.json()['access_token']
            print("CSSM Get Access Token returned access_token: ", self.access_token)
            # We are not validating refresh_token because we are asking user not to select refresh token
            # option while registering for grant assuming that CSSM never use refresh_token
            # refresh_token = response.json()['refresh_token']
            self.access_token_expires_in = response.json()['expires_in']
            # logger.info("====>>>>    Success: Got OAuth Token    <<<<====\n\n")
        except Exception as e:
            # logger.error(e)
            # logger.error("Please check your username/password!")
            d['message'] = 'Please check your username/password!'
            print("CSSM Get Access Token returned error: ", e)
            return d

        d['access_token'] = self.access_token,
        d['token_type'] = token_type,
        d['expires_in'] = self.access_token_expires_in
        return d

    def GetSAVAList(self):
        d = dict()
        uri = "https://swapi.cisco.com/services/api/services/api/smart-accounts-and-licensing/v2/accounts/search"
        print("CSSM SAVA API call with access token: ", self.access_token)
        headers = {
            "Authorization": "Bearer " + self.access_token,
            "Content-Type": "application/json",
            "Cache-Control": "no-cache"
        }
        response = requests.request("GET", uri, headers=headers)
        print("CSSM API SAVA List response: ", response.text)
        try:
            json_resp = response.json()
            if('status' in json_resp.keys()):
                if(json_resp['status'] != "COMPLETE"):
                    print("CSSM Get SAVA response status: ", json_resp['status'])
                    d['message'] = 'Failed'
                    return d
            else:
                print("CSSM Get SAVA response failed")
                d['message'] = 'Failed'
                return d
            print("CSSM Get SAVA response SUCCESS with status: ", json_resp['status'])
            if(len(json_resp['accounts']) == 0):
                print("CSSM Get SAVA response has 0 accounts")
                d['message'] = 'No valid accounts for this user'
                return d
            print("Accounts: ", json_resp['accounts'])

            sa = json_resp['accounts'][0]
            self.sa_domain = sa['domain']
            self.sa_id = sa['account_id']
            if(len(sa['virtual_accounts']) == 0):
                print("CSSM Get SAVA response has 0 VAs")
                d['message'] = 'No valid virtual accounts for this user'
                return d

            va = sa['virtual_accounts'][0]
            self.va_name = va['name']
            self.va_id = va['virtual_account_id']

        except Exception as e:
            d['message'] = 'Please check your username/password!'
            print("Got SAVA List execption: ", e)
            return d

        d['sa_id'] = self.sa_id,
        d['va_id'] = self.va_id,
        return d


    def SetSAVA(self, sa, va):
        self.sa_domain = sa
        self.va_name = va


    def SendRumReports(self):
        d = dict()
        uri = "https://swapi.cisco.com/services/api/services/api/smart-accounts-and-licensing/v2/accounts/search"
        print("CSSM SAVA API call with access token: ", self.access_token)
        headers = {
            "Authorization": "Bearer " + self.access_token,
            "Content-Type": "application/json",
            "Cache-Control": "no-cache"
        }
        response = requests.request("GET", uri, headers=headers)
        print("CSSM API SAVA List response: ", response.text)
        return


    def Poll():
        return


def read_config():
    try:
        with open("./config.yaml", 'r') as yamlfile:
            cfg = yaml.load(yamlfile)
        return cfg
    except Exception:
        print("Yaml file incomplete or invalid format")
        raise
    return


def run_offline_rum():
    cfg = read_config()
    cssm = CSSM('off', cfg)

    ''' Steps:
    1. LOCAL: Select SA, VA to be used for SLP from config
    2. Browse dev_info. For each device:
        a. Device API: Close open RUM reports
        b. Device API: Get all reports
        c. LOCAL: Format RUM reports as needed for offline upload
    3. LOCAL: Create a tarball for upload as per config path
    4. LOCAL: Read ACK from CSSM from the config path when available
    5. For each device in dev_info_poll:
        a. Extract response payload and do base64 encode
        b. Call Device API (import) to send ACK
        c. Remove device from device_poll_info
    '''

    '''

    # Step 3. Select SA, VA to be used for SLP (Alrady done in step-2 API)
    print("SA ID: ", sava_rsp['sa_id'], " VA ID: ", sava_rsp['va_id'])
    '''
    # 4. Browse dev_info. For each device:
    num_devices = len(cfg['devices'])
    print("Number of devices in sl-app-config.yaml: ", num_devices)
    # Create dir structure and manifesto file for offline upload to CSSM
    now = datetime.now()
    curr_time = now.strftime("%y%b%d_%H_%M_%S_%f")[:-3]
    work_path = cfg['rum_folder'] + "/tmp_" + curr_time
    Path(work_path).mkdir(parents=True, exist_ok=True)
    mfname = work_path + "/manifest.mf"
    mf = open(mfname, "w")

    mf.write('Manifest-Version: 1.0\nCreated-By: "{\\"uuid\\": \\"foofoo\\"}"\nSmart-Account:\nSmart-Account-ID:\n\nName: /UD_VA_' + curr_time + '.ta.gz\nSpecification-VA: \nSpecification-VA-ID: \n')

    all_file_names = []
    all_devices = dict()
    for dev in cfg['devices']:
        d = Device(dev)
        all_devices[d.dev_id] = d
        #cssm_msg = '<?xml version="1.0" encoding="UTF-8"?><smartLicense>'
        cssm_msg = '<smartLicense>'
        # a. Device API: Close open RUM reports
        #d.CloseReports()

        # b. Device API: Get all reports
        json_resp = d.GetAllRumReports()
        #print("-- Device: ", dev['ip'], ", received RUM payload: ", json_resp)
        if('message' in json_resp.keys()):
            print("CSSM Get All RUM reprt API failed")
            return

        # c. Format RUM reports as needed by CSSM API
        i = 0
        print("-- Device: ", dev['ip'], ", number of reports: ", len(json_resp['usage']))
        for rum in json_resp['usage']:
            cssm_msg += '<RUMReport><![CDATA[' + json.dumps(rum) + ']]></RUMReport>'
            i += 1
        cssm_msg += '</smartLicense>'
        # d. CSSM API: Send RUM reports and get poll_id
        now = datetime.now()
        fname = work_path + "/dev_" + str(d.dev_id) + "_" + curr_time + ".txt"
        all_file_names.append(fname)
        f = open(fname, "w")
        f.write(cssm_msg)
        f.close()

    mf.close()

    va_tar_name = work_path+"/UD_VA_"+curr_time+"_py.tar.gz"
    sa_tar_name = work_path+"/UD_SA_"+curr_time+"_py.tar.gz"
    with tarfile.open(va_tar_name, "w:gz") as va_tar:
        for name in all_file_names:
            print("Adding file ", name, " to ", va_tar_name)
            va_tar.add(name, arcname=os.path.basename(name))
    with tarfile.open(sa_tar_name, "w:gz") as sa_tar:
        print("Adding file ", mfname, " and ", va_tar_name, " to creat ", sa_tar_name)
        sa_tar.add(mfname, arcname=os.path.basename(mfname))
        sa_tar.add(va_tar_name, arcname=os.path.basename(va_tar_name))
    return


def Import_file(dev, in_fname):
    with open(in_fname) as xml_file:
        str_import = xml_file.read()
        json_import = xmltodict.parse(str_import)
        xml_file.close() 
        if 'smartLicense' not in json_import.keys():
            print("Input file is format not a valid")
            return
        if 'smartLicenseRumAck' not in json_import['smartLicense'].keys():
            print("Rum ACK not in Input file")
            num_ack = 0
            return
        if 'data' not in json_import['smartLicense']['smartLicenseRumAck'].keys():
            num_ack = 0
            return
        num_ack = 1
        print("smartLicense->smartLicenseRumAck->data type is: ", type(json_import['smartLicense']['smartLicenseRumAck']['data']))
        if 'smartLicensePolicy' not in json_import['smartLicense'].keys():
            num_policies = 0
        else:
            num_policies = len(json_import['smartLicense']['smartLicensePolicy'])
        print("Importing file: ", in_fname, ", num ACKs: ", num_ack, "num policies: ", num_policies)

        json_resp = dev.Import(str_import)
    return


def run_offline_ack(in_fname):
    cfg = read_config()
    dir_name = cfg['ack_folder']

    cssm = CSSM('off', cfg)
    print("Importing file: ", in_fname)
    # Create device dict on id from config
    all_devices = dict()
    for dev in cfg['devices']:
        d = Device(dev)
        all_devices[d.dev_id] = d
    tar = tarfile.open(in_fname, "r:gz")
    for tarinfo in tar:
        print("  Extracting ", tarinfo.name)
        tar.extract(tarinfo, dir_name)
        if "ACK_UD_VA" in tarinfo.name:
            if ".tar.gz" in tar.name:
                va_tar_name = dir_name + "/" + tarinfo.name
    tar.close()
    print("Further extracting: ", va_tar_name)
    vatar = tarfile.open(va_tar_name, "r:gz")
    for vatarinfo in vatar:
        print("  Extracting ", vatarinfo.name)
        vatar.extract(vatarinfo, dir_name)
        if "ACK_dev_" in vatarinfo.name:
            #ack_fname = vatarinfo.name
            l = vatarinfo.name.split('_')
            dev_id = int(l[2])
            print("ACK " , vatarinfo.name, " has id: ", dev_id)
            if dev_id in all_devices.keys():
                d = all_devices[dev_id]
                Import_file(d, vatarinfo.name)
            else:
                print("ID not found in ack file: ", vatarinfo.name)
    vatar.close()
    shutil.rmtree(dir_name)
    return


def run_online():
    ''' Steps:
    1. CSSM API: Use username/password and create access token
    2. CSSM API: Get list of SAs and VAs using access token
    3. LOCAL: Select SA, VA to be used for SLP
    4. Browse dev_info. For each device:
        a. Device API: Close open RUM reports
        b. Device API: Get all reports
        c. LOCAL: Format RUM reports as needed by CSSM API
        d. CSSM API: Send RUM reports and get poll_id
        e. LOCAL: store poll-ID list for that device in device_poll_info
    5. LOCAL: Wait for 30 seconds
    6. For each device in dev_info_poll:
        a. CSSM API: Poll for response
        b. LOCAL: If success response, then:
            i.   Extract response payload and do base64 encode
            ii.  Call Device API (import) to send ACK
            iii. Remove device from device_poll_info
    7. LOCAL: If device_poll_info is not empty then go to step 5
    '''

    # Step 1: Use username/password and create access token
    cfg = read_config()
    cssm = CSSM('on', cfg)
    token_rsp = cssm.GetAccessToken()
    if('message' in token_rsp.keys()):
        print("CSSM get access token failed with message: " + token_rsp['message'])
        return

    # print("Access token: ", token_rsp['access_token'])

    # Step 2. Get list of SAs and VAs using access token
    sava_rsp = cssm.GetSAVAList()
    if('message' in token_rsp.keys()):
        print("CSSM Get SAVA API failed")
        return
    return


if __name__ == "__main__":
    print("Select mode:")
    print("  (1) Online CSSM: API to get list of SA/VA")
    print("  (2) Offline CSSM: Collect RUM reports using IOS-XE API and upload offline")
    print("  (3) Offline CSSM: Apply RUM ACK using IOS-XE API (One device at a time)")
    value = input("Choice: ")
    if value == '1':
        run_online()
    elif value == '2':
        run_offline_rum()
    elif value == '3':
        fname = input("Input file name with path: ")
        run_offline_ack(fname)


