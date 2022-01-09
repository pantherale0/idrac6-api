import os
import paho.mqtt.client as mqtt
import requests
import xml.etree.ElementTree as ET
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import logging
from bs4 import BeautifulSoup

### Conversion utils
from lxml import objectify
import json

### Use threading for the active connection checker
import threading

class IDRAC6_API():
    def __init__(self, ip_addr, username, password, debug=False):
        self.ip_addr = ip_addr
        if debug:
            debug_level = logging.DEBUG
        else:
            debug_level = logging.INFO

        self.logger = self.initialize_logger(debug_level)

        self.session = requests.Session()
        self.do_login(self.url, username, password)

    def url(self):
        return 'https://' + self.ip_addr

    def initialize_logger(self, debug_level):
        """
        Initializes the logger object
        :return:
        """
        logger = logging.getLogger("IDRAC6_API")

        # This is for writing to files
        hdlr = logging.FileHandler('IDRAC6-Inteaction.log')
        formatter = logging.Formatter('%(asctime)s - [%(threadName)-12.12s] [%(levelname)s] %(message)s')
        hdlr.setFormatter(formatter)
        logger.addHandler(hdlr)

        # This is for console output
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)

        logger.addHandler(stream_handler)

        logger.setLevel(debug_level)
        logger.info('Application Started')
        return logger

    def do_login(self, url, username, password):
        self.get_index_request()  # gets the web cookie
        self.get_login_index_request()
        self.login_request(username, password)

    def get_index_request(self):
        url = self.url() + '/index.html'
        payload = ""
        headers = {
            'cache-control': "no-cache",
        }

        response = self.session.get(url, data=payload, headers=headers, verify=False)
        response_cookies = response.cookies._cookies
        self.logger.debug(response_cookies)

        if response_cookies.get(self.ip_addr, None) is not None:
        
            cookies_from_host = response_cookies[self.ip_addr]
            slash_cookie = cookies_from_host["/"]
            app_session_cookie = slash_cookie['_appwebSessionId_']
            self.auth_cookie = app_session_cookie.name + "=" + app_session_cookie.value + ";"

    def get_login_index_request(self):
        url = self.url() + "/login.html"
        payload = ""
        headers = {
            'cache-control': "no-cache",
            'Cookie': self.auth_cookie
        }

        response = self.session.get(url, data=payload, headers=headers, verify=False)

    def login_request(self, username, password):
        url = self.url() + "/data/login"

        payload = "user={}&password={}".format(username, password)
        headers = {
            'User-Agent': "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:65.0) Gecko/20100101 Firefox/65.0",
            'Accept': "*/*",
            'Accept-Language': "en-US,en;q=0.5",
            'Content-Type': "application/x-www-form-urlencoded",
            'Connection': "keep-alive",
            'cache-control': "no-cache",
            'Cookie': self.auth_cookie
        }

        response = self.session.post(url, data=payload, headers=headers, verify=False)
        self.logger.debug("Login request response " + response.text)
        tree = ET.ElementTree(ET.fromstring(response.text))
        root = tree.getroot()
        authResult = root.find("authResult")
        if authResult.text == '0':
            el = root.find("forwardUrl")
            redirect_string = el.text
            ST1_string = redirect_string[redirect_string.index("=") + 1:]

            ST1, STI2 = ST1_string.split(",ST2=")

            self.ST1 = ST1
            self.ST2 = STI2

            self.go_to_index_page(redirect_string)
            
            self.loggedIn = True
            # Create our new thread for connection testing
            thread = threading.Thread(target=self.active_connection_checker, args=(1,), daemon=True)
            thread.start()
        else:
            self.logger.error('Auth failed with status code ' + authResult.text)
            raise ConnectionError('Authentication failed')

    def go_to_index_page(self, redirect):
        url = self.url() + "/" + redirect
        headers = {
            'User-Agent': "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:65.0) Gecko/20100101 Firefox/65.0",
            'Accept': "*/*",
            'Accept-Language': "en-US,en;q=0.5",
            'Content-Type': "application/x-www-form-urlencoded",
            'Connection': "keep-alive",
            'cache-control': "no-cache",
            'ST2': self.ST2,
            'ST1': self.ST1,
            'Cookie': self.auth_cookie
        }

        response = self.session.get(url, headers=headers, verify=False)

    def active_connection_checker(self, interval=30):
        logging.info("Connection active, starting keepalive")
        while self.loggedIn:
            logging.debug("Starting status check on pwState")
            try:
                logging.debug("ampReading1 value: " + str(self.get_power_info().ampReading1))
                self.loggedIn=True
            except:
                ### Exception occured, probably need to re-authenticate
                self.loggedIn=False
                break
            time.sleep(interval)

        logging.info("Connection no longer active")
            

    def logout(self):
        import requests

        url = self.url() + "/data/logout"

        headers = {
            'User-Agent': "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:65.0) Gecko/20100101 Firefox/65.0",
            'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            'Accept-Language': "en-US,en;q=0.5",
            'Referer': "https://192.168.0.133/globalnav.html",
            'Connection': "keep-alive",
            'Cookie': self.auth_cookie,
            'Upgrade-Insecure-Requests': "1",
            'cache-control': "no-cache",
        }

        response = requests.request("GET", url, headers=headers, verify=False)
        self.loggedIn=False

        
    def send_request(self, url, querystring, outputAsObj=True):
        payload = "e="
        headers = {
            'Accept': "*/*",
            'Content-Type': "application/x-www-form-urlencoded",
            'ST2': self.ST2,
            'Connection': "keep-alive",
            'cache-control': "no-cache",
            'Cookie': self.auth_cookie
        }

        response = requests.request("POST", url, data=payload, headers=headers, params=querystring, verify=False)
        if outputAsObj:
            return objectify.fromstring(response.text)
        else:
            return response

    def get_bytes(self, url):
        import io
        payload = "e="
        headers = {
            'Accept': "*/*",
            'Content-Type': "application/x-www-form-urlencoded",
            'ST2': self.ST2,
            'Connection': "keep-alive",
            'cache-control': "no-cache",
            'Cookie': self.auth_cookie
        }

        return io.BytesIO(requests.request("GET", url, data=payload, headers=headers, verify=False).content)

    def get_attribute(self, attribute):
        url = self.url() + "/data"
        querystring = {"get": attribute + ","}
        response = self.send_request(url, querystring)
        self.logger.debug("get_attribute request response " + str(getattr(response, attribute)))
        return getattr(response, attribute)


    def set_attribute(self, attribute, value):
        url = self.url() + "/data"
        querystring = {"set": attribute + ":" + value}
        response = self.send_request(url, querystring)
        self.logger.debug("set_attribute response " + str(response.text))
        return self.get_attribute(attribute)


    def get_sensors(self, name):
        url = self.url() + "/data"
        querystring = {"get": "batteries,fansRedundancy,fans,intrusion,psRedundancy,powerSupplies,rmvsRedundancy,removableStorage,temperatures,voltages"}
        sensors = self.send_request(url, querystring)
        return sensors
        
    def get_power_status(self):
        return self.get_attribute("pwState")
    
    def get_device_info(self):
        url = self.url() + "/data"
        querystring = {"get": "svcTag,biosVer,fwVersion"}
        response = self.send_request(url,querystring)
        self.logger.debug("get_device_info request response received")
        return response

    def get_active_sessions(self):
        url = self.url() + "/data"
        querystring = {"get": "activeSessions"}
        response = self.send_request(url,querystring)
        self.logger.debug(" request response received")
        return response

    def kill_session(self, sessionId):
        url = self.url() + "/data"
        # First get active sessions
        activeSessions = self.get_active_sessions()

        for sessionData in activeSessions.sessionList.session:
            if sessionData.sessionId == sessionId:
                querystring = {"set": "killSession(" + sessionData.sessionId + ")"}
                response = self.send_request(url, querystring)
                self.logger.debug("kill_session request response received")
                break

    def get_idrac_firmware_info(self):
        url = self.url() + "/data"
        querystring = {"get": "racName,productInformation,hwVersion,fwVersion,fwUpdated,datetime,ipmiMaxSessions,ipmiSessionCount,netEnabled,ipmiVersion,macAddr,netMode,v4Enabled,v4DHCPEnabled,v4IPAddr,v4Gateway,v4NetMask,v4DHCPServers,v4DNS1,v4DNS2,v6Enabled,v6DHCPEnabled,v6Addr,v6Gateway,v6DHCPServers,v6DNS1,v6DNS2,v6LinkLocal,v6Prefix,v6SiteLocal,v6SiteLocal3,v6SiteLocal4,v6SiteLocal5,v6SiteLocal6,v6SiteLocal7,v6SiteLocal8,v6SiteLocal9,v6SiteLocal10,v6SiteLocal11,v6SiteLocal12,v6SiteLocal13,v6SiteLocal14,v6SiteLocal15,"}
        response = self.send_request(url, querystring)
        self.logger.debug("get_idrac_firmware_info request response received")
        return response

    def get_idrac_kvm_info(self):
        url = self.url() + "/data"
        querystring = {"get": "kvmEnabled,kvmMaxSessions,kvmActSes,kvmPort,kvmEncEnabled,localVideo,kvmPluginType,vmActSes,vmEncEnabled,vmFloppyEmul,vmAttachStatus,vmActSes,vfkEnable,bootonceEnabled,kvmPort,webHTTPPort,webHTTPSPort,sshPort,telnetPort,remoteSyslogPort,xGLServerPort,"}
        response = self.send_request(url, querystring)
        self.logger.debug("get_idrac_kvm_info request response received")
        return response

    def get_power_info(self):
        url = self.url() + "/data"
        querystring = {"get": "powermonitordata,systemLevel,voltages"}
        response = self.send_request(url, querystring)
        self.logger.debug("get_power_info request response received")
        return response

    def get_screen_capture(self):
        import time, datetime
        url = self.url() + "/capconsole/scapture0.png?" + str(int(time.time() * 1000))
        return self.get_bytes(url)

    def get_last_crash_screen(self):
        url = self.url() + "/capdata/bsod.png"
        return self.get_bytes(url)

    def get_remote_fileshare_info(self):
        url = self.url() + "/data"
        querystring = {"get": "remoteFileshrUser,remoteFileshrPwd,remoteFileshrImage,remoteFileshrStatus,"}
        response = self.send_request(url, querystring)
        self.logger.debug("get_remote_fileshare request response received")
        return response

    def get_vflash_info(self):
        url = self.url() + "/data"
        querystring = {"get": "vfkListSDInfoDell,vfkLicense,amea_sd_present,vmActSes,"}
        response = self.send_request(url, querystring)
        self.logger.debug("get_vflash_info request response received")
        return response

    def get_last_boot_capture_info(self):
        url = self.url() + "/data"
        querystring = {"get": "bootCapFileData"}
        response = self.send_request(url, querystring)
        self.logger.debug("get_last_boot_capture_info request response received")
        return response

    def get_idrac_users(self):
        url = self.url() + "/data"
        querystring = {"get": "users,"}
        response = self.send_request(url, querystring)
        self.logger.debug("get_idrac_users request response received")
        return response

    def get_idrac_directory_service(self):
        url = self.url() + "/data"
        querystring = {"get": "LDAPEnableMode,LDAPEnableMode"}
        response = self.send_request(url, querystring)
        self.logger.debug("get_idrac_users request response received")
        return response

    def get_idrac_certificate(self):
        url = self.url() + "/data"
        querystring = {"get": "certificate"}
        response = self.send_request(url, querystring)
        self.logger.debug("get_idrac_users request response received")
        return response

    def get_idrac_certificate_defaults(self):
        url = self.url() + "/data"
        querystring = {"get": "commonName,orgName,orgUnit,locality,stateName,countryCode,email,"}
        response = self.send_request(url, querystring)
        self.logger.debug("get_idrac_users request response received")
        return response

    def generate_idrac_csr(self, commonName, orgName, orgUnit, locality, stateName, countryCode, email):
        import urllib, urllib.parse
        url = self.url() + "/bindata"
        querystring = {"set": 'serverCSR({cn},{org},{unit},{locality},{state},{country},{email})'.format(
            cn=urllib.parse.quote_plus(commonName),
            org=urllib.parse.quote_plus(orgName),
            unit=urllib.parse.quote_plus(orgName),
            locality=urllib.parse.quote_plus(locality),
            state=urllib.parse.quote_plus(stateName),
            country=urllib.parse.quote_plus(countryCode),
            email=urllib.parse.quote_plus(email))}

        response = self.send_request(url, querystring, False)
        self.logger.debug("generate_idrac_csr request response received")
        return response.text

    def get_idrac_serial_info(self):
        url = self.url() + "/data"
        querystring = {"get": "racSerialEnabled,racTimeout,racRedirectEna,racBaud,racEscKey,racHistBuf,racLoginCmd,ipmiConMode,ipmiBaud,ipmiFlow,ipmiPrivLevel,scEnabled,serialOverLanEnabled,serialOverLanBaud,serialOverLanPriv,"}
        response = self.send_request(url, querystring)
        self.logger.debug("get_idrac_serial_info request response received")
        return response

    def get_idrac_services_info(self):
        url = self.url() + "/data"
        querystring = {"get": "webEnabled,webMaxSessions,webSessionCount,webTimeout,sshEnabled,sshTimeout,telnetEnabled,telnetTimeout,racadmEnabled,racadmSessionCount,snmpEnabled,snmpCommunityServices,asrEnabled,scEnabled,romDisabled,racadmDisabled,sshMaxSessions,sshSessionCount,telnetMaxSessions,telnetSessionCount,websslEncryption,kvmPort,webHTTPPort,webHTTPSPort,sshPort,telnetPort,remoteSyslogPort,xGLServerPort,"}
        response = self.send_request(url, querystring)
        self.logger.debug("get_idrac_services_info request response received")
        return response

    def get_idrac_smartcard_info(self):
        url = self.url() + "/data"
        querystring = {"get": "scEnabled,scCRLCheck,"}
        response = self.send_request(url, querystring)
        self.logger.debug("get_idrac_smartcard_info request response received")
        return response

    def get_rac_log_entries(self):
        url = self.url() + "/data"
        querystring = {"get": "racLogEntries"}
        response = self.send_request(url, querystring)
        self.logger.debug("get_rac_log_entries request response received")
        return response

    def get_system_event_log_entries(self):
        url = self.url() + "/data"
        querystring = {"get": "eventLogEntries"}
        response = self.send_request(url, querystring)
        self.logger.debug("get_system_event_log_entries request response received")
        return response

