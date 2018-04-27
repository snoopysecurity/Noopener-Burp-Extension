from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.io import PrintWriter
from java.net import URL
from java.util import ArrayList, List
from java.util.regex import Matcher, Pattern


class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Noopener Extension")

        callbacks.issueAlert("Noopener Passive Scanner check enabled")

        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.registerScannerCheck(self)

    def doPassiveScan(self, ihrr):
        response = self.helpers.bytesToString(ihrr.getResponse())
        p = Pattern.compile('target=(\"|\').*_blank(\"|\')(?!\s*rel=(\"|\')noopener(\"|\'))(?!\s*rel=(\"|\')noreferrer(\"|\'))', Pattern.DOTALL)
        m = p.matcher(response)
        if "target=" in response and m.find():
            issues = ArrayList()
            issues.add(noopener(ihrr))
            return issues

        return None

    def doActiveScan(self, ihrr, isip):
        return None  

    def consolidateDuplicateIssues(self, isb, isa):
        return -1


class noopener(IScanIssue):
    def __init__(self, reqres):
        self.reqres = reqres

    def getHost(self):
        return self.reqres.getHost()

    def getPort(self):
        return self.reqres.getPort()

    def getProtocol(self):
        return self.reqres.getProtocol()

    def getUrl(self):
        return self.reqres.getUrl()

    def getIssueName(self):
        return "Target=\"_blank\" attribute set without security values"

    def getIssueType(self):
        return 0x08000000  

    def getSeverity(self):
        return "Information"  

    def getConfidence(self):
        return "Certain"  

    def getIssueBackground(self):
        return str("The target attribute specifies the context in where a linked resource"
                      " will open when the it is clicked by a user. Links opened via target "
                      "blank attributes have the ability to make changes to the original page."
                      "This could be leveraged to conduct phishing attacks.")

    def getRemediationBackground(self):
        return "References: <ul><li><a href='https://mathiasbynens.github.io/rel-noopener/'>About rel=noopener</a></li><li><a href='https://snoopysecurity.github.io/2018/04/26/target-blank-vulnerability.html'>The target='_blank' Vulnerability</a></li></ul>"

    def getIssueDetail(self):
        return str("Burp identified the target=\"_blank\" attribute being used without the noopener and noreferrer attribute in the following page: <b>"
                      "%s</b><br>" % (self.reqres.getUrl().toString()))

    def getRemediationDetail(self):
        return str("The 'noopener' and 'noreferrer' attribute can be used to prevent pages from gaining access to the window.opener.location property and abuse this vulnerability.")

    def getHttpMessages(self):
        rra = [self.reqres]
        return rra

    def getHttpService(self):
        return self.reqres.getHttpService()
