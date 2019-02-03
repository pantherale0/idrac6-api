import requests
import xml.etree.ElementTree as ET
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import logging

class IDRAC6_API():

    def __init__(self, url, username, password, debug=False):
        self.url = url

        if debug:
            debug_level = logging.DEBUG
        else:
            debug_level = logging.INFO

        self.logger = self.initialize_logger(debug_level)

        self.session = requests.Session()
        self.do_login(url, username, password)

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

    @property
    def ip_addr(self):
        return self.url.replace("https://", "")

    def do_login(self, url, username, password):
        self.get_index_request()  # gets the web cookie
        self.get_login_index_request()
        self.login_request(username, password)

    def get_index_request(self):
        url = self.url + "/index.html"
        payload = ""
        headers = {
            'cache-control': "no-cache",
        }

        response = self.session.get(url, data=payload, headers=headers, verify=False)

        response_cookies = response.cookies._cookies
        if response_cookies.get(self.ip_addr, None) is not None:
            cookies_from_host = response_cookies[self.ip_addr]

            slash_cookie = cookies_from_host["/"]
            app_session_cookie = slash_cookie['_appwebSessionId_']
            self.auth_cookie = app_session_cookie.name + "=" + app_session_cookie.value + ";"

    def get_login_index_request(self):
        url = self.url + "/login.html"
        payload = ""
        headers = {
            'cache-control': "no-cache",
            'Cookie': self.auth_cookie
        }

        response = self.session.get(url, data=payload, headers=headers, verify=False)
        # print(response.text)

    def login_request(self, username, password):
        url = self.url + "/data/login"

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
        el = root.find("forwardUrl")
        redirect_string = el.text
        ST1_string = redirect_string[redirect_string.index("=") + 1:]

        ST1, STI2 = ST1_string.split(",ST2=")

        self.ST1 = ST1
        self.ST2 = STI2

        self.go_to_index_page(redirect_string)

    def go_to_index_page(self, redirect):
        url = self.url + "/" + redirect
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

    def logout(self):
        import requests

        url = self.url + "/data/logout"

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

        #self.logger.debug("logout request response " + response.text)

    def get_power_status(self):
        url = self.url + "/data"

        querystring = {"get": "pwState,"}

        payload = "e="
        headers = {
            'User-Agent': "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:65.0) Gecko/20100101 Firefox/65.0",
            'Accept': "*/*",
            'Accept-Language': "en-US,en;q=0.5",
            'Referer': "https://192.168.0.133/powercontrol.html?cat=C00&tab=T02&id=P05",
            'Content-Type': "application/x-www-form-urlencoded",
            'ST2': self.ST2,
            'Connection': "keep-alive",
            'cache-control': "no-cache",
            'Cookie': self.auth_cookie
        }

        response = requests.request("POST", url, data=payload, headers=headers, params=querystring, verify=False)

        self.logger.debug("get_power_status request response " + response.text)
        tree = ET.ElementTree(ET.fromstring(response.text))
        root = tree.getroot()
        el = root.find("pwState")
        return el.text

    def set_power_status(self, state:int):

        url = self.url + "/data"

        querystring = {"set": "pwState:{}".format(int(state))}

        headers = {
            'User-Agent': "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:65.0) Gecko/20100101 Firefox/65.0",
            'Accept': "*/*",
            'Accept-Language': "en-US,en;q=0.5",
            'Content-Type': "application/x-www-form-urlencoded",
            'ST2': self.ST2,
            'DNT': "1",
            'Connection': "keep-alive",
            'Cookie': self.auth_cookie,
            'cache-control': "no-cache",
        }

        response = requests.request("POST", url, headers=headers, params=querystring, verify=False)

        self.logger.debug("Set state response " + str(response.text))
