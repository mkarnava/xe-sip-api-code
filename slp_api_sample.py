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
    """
    A class to represent IOS-XE device or product instance running 
    Smart License Using Policcy (SLP) capable image with version like 
    17.2.2 or 17.4.1 or later.

    """
    dev_id = 0
    ip = ""
    username = ""
    password = ""


    def __init__(self, device):
        """
        The constructor for Device class.

        Parameters:
            device (dictionary) : A dictionary of parameters.
             key                 value
             id (string)         (int) unique identifier of device
             ip (string)         (string) IP address of device where HTTP server is running
             username (string)   (string) Device access credentials - username
             password (string)   (string) Device access credentials - password
        """
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
        """
        This function calls API GET /smartlic-service/list on Device to get 
        the SLP information table of contents (TOC) ans prints the usage_list
        from response received.

        Returns:
            None
        """
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
        """
        This function calls API GET /smartlic-service/all-reports on Device to get 
        the all signed RUM reports as json response.


        Returns:
            json resposne object
        """
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


    def Import_str(self, str_import):
        """
        This function calls API POST /smartlic-self/import on Device to 
        push the input string. The input string will be base64 encoded 
        before sending.

        Returns:
            None
        """
        url = "https://" + self.ip + "/smartlic-service/import"
        hdr = {
            'Content-Type': "application/json",
        }
        print("Import: received string len ", len(str_import))

        body = str_import.encode() 
        print("Import body type", type(body))

        my_json = body.decode('utf8').replace("'", '"')
        #print("my_json: ", my_json)

        try:
            response = requests.request("POST", url, auth=(self.username, self.password), headers=hdr, verify=False, data=my_json, timeout=5)
            print("Device API: Import API response code: ", response.status_code)
        except Exception as e:
            print("Import failed for device ", self.ip, " with execption: ", e)

        return


    def CloseReports(self):
        """
        This function calls API POST /smartlic-self/close-reports on Device to 
        close all currently open RUM reports. It is required to close RUM reports 
        so that license usage till date can be captured in GET queries.

        Returns:
            None
        """
        url = "https://" + self.ip + "/smartlic-service/close-reports"
        hdr = {
            'Content-Type': "application/json",
        }
        body = {"test": ""}

        response = requests.request("POST", url, auth=(self.username, self.password), headers=hdr, verify=False, data=body, timeout=5)
        print("Device API: close RUM report response code: ", response.status_code)
        return


    def Import_ack_file(self, in_fname):
        """
        This function calls API POST /smartlic-self/import on Device to 
        push RUM ACK to the devices in the ACK file downloaded from CSSM.

        Returns:
            None
        """
        with open(in_fname) as xml_file:
            str_import = xml_file.read()
            json_import = xmltodict.parse(str_import)
            xml_file.close() 
            if 'smartLicense' not in json_import.keys():
                print("Input file format not a valid")
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
            json_resp = self.Import_str(str_import)
        return


    def Import_policy_file(self, in_fname):
        """
        This function calls API POST /smartlic-self/import on Device to 
        push custom policy file downloaded from CSSM.

        Returns:
            None
        """
        with open(in_fname) as xml_file:
            str_import = xml_file.read()
            json_import = xmltodict.parse(str_import)
            xml_file.close() 
            if 'smartLicensePolicy' not in json_import.keys():
                print("Input file format not a valid")
                return
            json_resp = self.Import_str(str_import)
        return


class CSSM:
    """
    A class to represent CSSM for online API calls or offline file IO.

    """
    def __init__(self, cssm_access_type, cfg):
        """
        The constructor for Device class.

        Parameters:
            cssm_access_type (string) :     should be any of 'on' or 'off'
            cfg (dictionary) : A dictionary of parameters parsed from .yaml config
        """
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
        """
        This function calls CSSM API GET https://cloudsso.cisco.com/as/token.oauth2 
        to get access token for future API calls and save it as a private member.

        Returns:
            dictionary d['access_token'], d['token_type'], d['expires_in'], d['message']
        """
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
            # refresh_token not validated here
            self.access_token_expires_in = response.json()['expires_in']
            print("====>>>>    Success: Got OAuth Token    <<<<====\n\n")
        except Exception as e:
            d['message'] = 'Please check your username/password!'
            print("CSSM Get Access Token returned error: ", e)
            return d

        d['access_token'] = self.access_token,
        d['token_type'] = token_type,
        d['expires_in'] = self.access_token_expires_in
        return d

    def GetSAVAList(self):
        """
        This function calls CSSM API GET https://swapi.cisco.com/services/api/services/api/smart-accounts-and-licensing/v2/accounts/search 
        to query all SA and VA that the use has access to. It prints 
        the information received.

        Returns:
            None
        """
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
        """
        This function sets SA nad VA memebrs of the class.

        Parameters:
            sa (string) : Smart account name as string
            va (string) : Virtual account name as string

        Returns:
            None.
        """
        self.sa_domain = sa
        self.va_name = va


def read_config():
    """
    This function reads config from ./sl-app-config.yaml

        Parameters:
            None.

        Returns:
            None.
        """
    try:
        with open("./sl-app-config.yaml", 'r') as yamlfile:
            cfg = yaml.load(yamlfile)
        return cfg
    except Exception:
        print("Yaml file incomplete or invalid format")
        raise
    return


def run_offline_rum():
    """
    This function collects RUM reports from all devices in the config file 
    and prepares a tarball in a format that CSSM UI can accept as a manual 
    upload.

    Parameters:
        None.

    Returns:
        None.
    """
    cfg = read_config()
    cssm = CSSM('off', cfg)

    # Browse dev_info. For each device:
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
        cssm_msg = '<smartLicense>'
        # Device API: Close open RUM reports
        d.CloseReports()
        # Device API: Get all reports
        json_resp = d.GetAllRumReports()
        if('message' in json_resp.keys()):
            print("CSSM Get All RUM reprt API failed")
            return
        # Format RUM reports as needed by CSSM UI as per offline uplaod format
        i = 0
        print("-- Device: ", dev['ip'], ", number of reports: ", len(json_resp['usage']))
        for rum in json_resp['usage']:
            cssm_msg += '<RUMReport><![CDATA[' + json.dumps(rum) + ']]></RUMReport>'
            i += 1
        cssm_msg += '</smartLicense>'
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
            os.remove(name)
    with tarfile.open(sa_tar_name, "w:gz") as sa_tar:
        print("Adding file ", mfname, " and ", va_tar_name, " to creat ", sa_tar_name)
        sa_tar.add(mfname, arcname=os.path.basename(mfname))
        sa_tar.add(va_tar_name, arcname=os.path.basename(va_tar_name))
    os.remove(mfname)
    os.remove(va_tar_name)
    return


def run_offline_ack(in_fname):
    """
    This function processes offline RUM ACT downloaded from CSSM UI and then 
    uploads them to the devices. The devices needs to be in the config.yaml file
    with same device ID as it was while collecting the RUM reports for offline 
    upload on CSSM. 

    Parameters:
        in_fname (string) : Filename of the ACK file downloaded from CSSM.

    Returns:
        None.
    """
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
            l = vatarinfo.name.split('_')
            dev_id = int(l[2])
            ack_fname = dir_name + "/" + vatarinfo.name
            print("ACK " , ack_fname, " has id: ", dev_id)
            if dev_id in all_devices.keys():
                d = all_devices[dev_id]
                d.Import_ack_file(ack_fname)
            else:
                print("ID not found in ack file: ", ack_fname)
    vatar.close()
    shutil.rmtree(dir_name)
 
    return


def run_offline_policy(in_fname):
    """
    This function applies custom policy to all devices in the config file.
    The custom policy file should be downloaded from CSSM.

    Parameters:
        in_fname (string) : Filename of the custom policy downloaded from CSSM.

    Returns:
        None.
    """
    cfg = read_config()

    cssm = CSSM('off', cfg)
    print("Importing file: ", in_fname)
    # Create device dict on id from config
    all_devices = dict()
    for dev in cfg['devices']:
        d = Device(dev)
        all_devices[d.dev_id] = d
        print("Pushing policy file to device: ", d.ip, " File: ", in_fname)
        d.Import_policy_file(in_fname)
    return


def run_online():
    """
    This function is to demonstate online CSSM API calls. It reads config
    and calls CSSM API to generate Access Token. Then using this Access 
    Token, it calls SA/VA search CSSM API and prints the results.

    Parameters:
        None.

    Returns:
        None.
    """

    # Step 1: Use username/password and create access token
    cfg = read_config()
    cssm = CSSM('on', cfg)
    token_rsp = cssm.GetAccessToken()
    if('message' in token_rsp.keys()):
        print("CSSM get access token failed with message: " + token_rsp['message'])
        return

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
    print("  (4) Offline CSSM: Apply custom-policy to all devices")
    value = input("Choice: ")
    if value == '1':
        run_online()
    elif value == '2':
        run_offline_rum()
    elif value == '3':
        fname = input("Input file name with path: ")
        run_offline_ack(fname)
    elif value == '4':
        fname = input("Input policy file name with path: ")
        run_offline_policy(fname)
