import requests, json, sys
import logging
from requests import Request, Session
from distutils.version import LooseVersion, StrictVersion

#Globals, should be configured to match your environment
adminUser = 'admin'
adminPass = 'bigip123'
host = 'https://10.3.17.10'
managementPath = '/mgmt/tm/'
minimumVersion = '11.6'
DEBUG=1

#Gui settings
guiBannerText = "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:\r\n\r\nThe USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\r\n\r\nAt any time, the USG may inspect and seize data stored on this IS.\r\nCommunications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose.\r\nThis IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\r\n\r\nNotwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

#HTTPD Settings
httpdMaxClients = '10'
httpdAuthPamIdleTimeout = '900'
httpdSslCiphersuite = 'ALL:!aNULL:!eNULL:!EXPORT:!EXP:!ADH:!DES:!RC4:!RSA:!LOW:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA'
httpdSslProtocol = 'all -SSLv2 -SSLv3 -TLSv1'

#NTP Settings
#Separate each ntp server with " "
ntpServersList = '192.168.5.1" "pool.ntp.org'
ntpTimezone = 'America/New_York'

#SSHD settings
sshdBannerText = "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:\r\n\r\nThe USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\r\n\r\nAt any time, the USG may inspect and seize data stored on this IS.\r\nCommunications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose.\r\nThis IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\r\n\r\nNotwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
sshdCipherString = 'aes128-ctr,aes192-ctr,aes256-ctr'
sshdMacString = 'hmac-sha1,hmac-ripemd160'
sshdTimeout = '900'
sshdProtocol = '2'
sshdMaxAuthTries = '3'

#Password Policy settings
passwordPolicyExpirationWarning = '7'
passwordPolicyMaxDuration = '90'
passwordPolicyMaxLoginFailures = '3'
passwordPolicyMinDuration = '1'
passwordPolicyMinimumLength = '8'
passwordPolicyPasswordMemory = '3'
passwordPolicyPolicyEnforcement = 'enabled'
passwordPolicyRequiredLowercase = '2'
passwordPolicyRequiredNumeric = '2'
passwordPolicyRequiredSpecial = '2'
passwordPolicyRequiredUppercase = '2'

#UI Advisory settings
uiAdvisoryEnabled = "true" #Values are true or false
classOrUnclass = "unclassified" #values are classified or unclassified
uiAdvisoryColorUnclass = "green" 
uiAdvisoryTextUnclass = "//UNCLASSIFIED//"
uiAdvisoryColorClass = "red" 
uiAdvisoryTextClass = "//CLASSIFIED//"

#SNMP Settings
snmpDefaultCommunity = '~Common~comm-public'

#iRule Settings
iRuleName = '_encrypt_http_cookies'



restHeaders = {
    'Accept': 'application/json',
   # 'Content-Type': 'application/json; charset=UTF-8'
     'Content-Type': 'application/json'
}




#Method to list objects
def restGet(uri,adminUser,adminPass):

		response = requests.get(uri,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
		return response

#Method to add objects
def restPost(uri,body,adminUser,adminPass):

		response = requests.post(uri,body,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
		return response

#Method to add objects
def restPostFileUpload(uri,files,adminUser,adminPass):

		response = requests.post(uri,files=files,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
		print(response.text)
		return response

#Method to modify existing objects, not create
def restPut(uri,body,adminUser,adminPass):

		response = requests.put(uri,body,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
		return response
		
#Method to delete
def restDelete(uri,adminUser,adminPass):

		response = requests.delete(uri,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
		return response
	
#Verify the active version has been tested	
def checkVersion():

	#curl -k -u admin:bigip123 -X GET https://10.3.1.10/mgmt/tm/sys/version/ | sed 's/,/\'$'\n/g'
	response = restGet(host + managementPath + 'sys/version/', adminUser, adminPass)
	responseJson = json.loads(response.text)
	activeVersionString = responseJson['entries']['https://localhost/mgmt/tm/sys/version/0']['nestedStats']['entries']['Version']['description'] 
	
	if ( StrictVersion(activeVersionString) < StrictVersion(minimumVersion)):
	
		print("Script has not been tested on TMOS versions below "  + minimumVersion + " Script will exit")
		sys.exit()
		
	else:
	
		print("Success:  Script has been successfully tested on this version.  Configuration will continue.")

def stigAppModeLite():

	appModeDisableBashStigJsonBody = '{ "value":"true"}'
	response = restPut(host + managementPath + 'sys/db/systemauth.disablebash', appModeDisableBashStigJsonBody, adminUser, adminPass)
	appModeDisableRootloginStigJsonBody = '{ "value":"true"}'
	response = restPut(host + managementPath + 'sys/db/systemauth.disablerootlogin', appModeDisableRootloginStigJsonBody, adminUser, adminPass)
	
def stigPasswordPolicy():	
	
	passwordPolicyJsonBody = '{ "expirationWarning":"' + passwordPolicyExpirationWarning + '","maxDuration":"' + passwordPolicyMaxDuration + '","maxLoginFailures":"' + passwordPolicyMaxLoginFailures + '","minDuration":"' + passwordPolicyMinDuration + '","minimumLength":"' + passwordPolicyMinimumLength + '","passwordMemory":"' + passwordPolicyPasswordMemory + '","policyEnforcement":"' + passwordPolicyPolicyEnforcement + '","requiredLowercase":"' + passwordPolicyRequiredLowercase + '","requiredNumeric":"' + passwordPolicyRequiredNumeric + '","requiredSpecial":"' + passwordPolicyRequiredSpecial + '","requiredUppercase":"' + passwordPolicyRequiredUppercase + '"}'
	print(passwordPolicyJsonBody)
	response = restPut(host + managementPath + 'auth/password-policy', passwordPolicyJsonBody, adminUser, adminPass)
	
def stigCallHome():

	callHomeStigJsonBody = '{ "autoCheck":"disabled"}'	
	response = restPut(host + managementPath + 'sys/software/update', callHomeStigJsonBody, adminUser, adminPass)	

def stigGuiBanner():

	guiStigJsonBody = '{ "guiSecurityBanner":"enabled", "guiSecurityBannerText": "' + guiBannerText + '"}'	
	response = restPut(host + managementPath + 'sys/global-settings', guiStigJsonBody, adminUser, adminPass)

def stigNtp():

	ntpStigJsonBody = '{  "servers":["' + ntpServersList + '"],"timezone":"' + ntpTimezone + '" }'
	response = restPut(host + managementPath + 'sys/ntp', ntpStigJsonBody, adminUser, adminPass)	

def stigSshd():

	sshdStigJsonBody = '{ "inactivityTimeout":"' +  sshdTimeout + '" ,"banner":  "enabled", "banner-text":"' +  sshdBannerText + '", "include":  "Protocol ' + sshdProtocol +  '\r\nMaxAuthTries ' + sshdMaxAuthTries + '\r\nCiphers ' + sshdCipherString + '\r\nMACs ' + sshdMacString + ' hmac-sha1,hmac-ripemd160" }'
	response = restPut(host + managementPath + 'sys/sshd', sshdStigJsonBody, adminUser, adminPass)	
	
def stigHttpd():

	httpdStigJsonBody = '{ "maxClients":"'  + httpdMaxClients + '" , "authPamIdleTimeout":"' + httpdAuthPamIdleTimeout + '", "sslCiphersuite":"' + httpdSslCiphersuite + '","sslProtocol":"' + httpdSslProtocol +  '" }'
	response = restPut(host + managementPath + 'sys/httpd', httpdStigJsonBody, adminUser, adminPass)	
	
def stigUiAdvisory():
	
	if uiAdvisoryEnabled == "true":
	
		uiAdvisoryEnableJsonBody = '{ "value":"' + uiAdvisoryEnabled + '"}'
		response = restPut(host + managementPath + 'sys/db/ui.advisory.enabled', uiAdvisoryEnableJsonBody, adminUser, adminPass)
	
		if classOrUnclass == "unclassified":
		
			uiAdvisoryColorJsonBody = '{ "value":"' + uiAdvisoryColorUnclass + '"}'
			response = restPut(host + managementPath + 'sys/db/ui.advisory.color', uiAdvisoryColorJsonBody, adminUser, adminPass)
	
			uiAdvisoryTextJsonBody = '{ "value":"' + uiAdvisoryTextUnclass + '"}'
			response = restPut(host + managementPath + 'sys/db/ui.advisory.text', uiAdvisoryTextJsonBody, adminUser, adminPass)
	
		else:
    		
			uiAdvisoryColorJsonBody = '{ "value":"' + uiAdvisoryColorClass + '"}'
			response = restPut(host + managementPath + 'sys/db/ui.advisory.color', uiAdvisoryColorJsonBody, adminUser, adminPass)
	
			uiAdvisoryTextJsonBody = '{ "value":"' + uiAdvisoryTextClass + '"}'
			response = restPut(host + managementPath + 'sys/db/ui.advisory.text', uiAdvisoryTextJsonBody, adminUser, adminPass)

#Do we want to remove all snmp or just default snmp
def stigSnmp():

	response = restDelete(host + managementPath + 'sys/snmp/communities/' + snmpDefaultCommunity , adminUser, adminPass)

#Rename admin user, if not local, will fail, so we must test if local or remote
def stigRenameAdmin():

	print("J")
	
def stigIrule():

	iRuleBody = "when RULE_INIT {\n \n\t# Cookie name prefix\n\tset static::ck_pattern 'BIGipServer*'\n \n\t# Log debug to /var/log/ltm? 1=yes, 0=no)\n\tset static::ck_debug 1\n \n\t# Cookie encryption passphrase\n\t# Change this to a custom string!\n\tset static::ck_pass 'mypass1234'\n}"
	
	#We must first create the iRule w/o any content
	iruleJsonBody = '{"name" : "' + iRuleName + '"}'
	response = restPost(host + managementPath + 'ltm/rule', iruleJsonBody, adminUser, adminPass)
	
	#For double quotes, the backslash must be escaped for the json parser	
	iruleJsonBody = '{"apiAnonymous" :'  + ' "when RULE_INIT {\n \n\t# Cookie name prefix\n\tset static::ck_pattern \\\"BIGipServer*\\\"\n \n\t# Log debug to /var/log/ltm? 1=yes, 0=no)\n\tset static::ck_debug 1\n \n\t# Cookie encryption passphrase\n\t# Change this to a custom string!\n\tset static::ck_pass \\\"mypass1234\\\"\n}\nwhen HTTP_REQUEST {\n \n\tif {$static::ck_debug}{log local0. \\\"Request cookie names: [HTTP::cookie names]\\\"}\n\t\n\t# Check if the cookie names in the request match our string glob pattern\n\tif {[set cookie_names [lsearch -all -inline [HTTP::cookie names] $static::ck_pattern]] ne \\\"\\\"}{\n \n\t\t# We have at least one match so loop through the cookie(s) by name\n\t\tif {$static::ck_debug}{log local0. \\\"Matching cookie names: [HTTP::cookie names]\\\"}\n\t\tforeach cookie_name $cookie_names {\n\t\t\t\n\t\t\t# Decrypt the cookie value and check if the decryption failed (null return value)\n\t\t\tif {[HTTP::cookie decrypt $cookie_name $static::ck_pass] eq \\\"\\\"}{\n \n\t\t\t\t# Cookie was not encrypted, delete it\n\t\t\t\tif {$static::ck_debug}{log local0. \\\"Removing cookie as decryption failed for $cookie_name\\\"}\n\t\t\t\tHTTP::cookie remove $cookie_name\n\t\t\t}\n\t\t}\n\t\tif {$static::ck_debug}{log local0. \\\"Cookie header(s): [HTTP::header values Cookie]\\\"}\n\t}\n}\nwhen HTTP_RESPONSE {\n \n\tif {$static::ck_debug}{log local0. \\\"Response cookie names: [HTTP::cookie names]\\\"}\n\t\n\t# Check if the cookie names in the request match our string glob pattern\n\tif {[set cookie_names [lsearch -all -inline [HTTP::cookie names] $static::ck_pattern]] ne \\\"\\\"}{\n\t\t\n\t\t# We have at least one match so loop through the cookie(s) by name\n\t\tif {$static::ck_debug}{log local0. \\\"Matching cookie names: [HTTP::cookie names]\\\"}\n\t\tforeach cookie_name $cookie_names {\n\t\t\t\n\t\t\t# Encrypt the cookie value\n\t\t\tHTTP::cookie encrypt $cookie_name $static::ck_pass\n\t\t}\n\t\tif {$static::ck_debug}{log local0. \\\"Set-Cookie header(s): [HTTP::header values Set-Cookie]\\\"}\n\t}}"}'
	response = restPut(host + managementPath + 'ltm/rule/' + iRuleName, iruleJsonBody, adminUser, adminPass)

def stigUploadCert():


	newCertPath = '/mgmt/shared/file-transfer/uploads/testuser'
	files = {'file' : open('testuser1.liquid.local.crt', 'rb')}
	s = Session()

	req = Request('POST', host + newCertPath, files=files,auth=(adminUser,adminPass))
	prepped = req.prepare()
	print(prepped.headers)
	resp = s.send(prepped,verify=False)
	print(resp)

	#response = restPostFileUpload(host + newCertPath, files, adminUser, adminPass)

def main():

	#checkVersion()
	#stigNtp()
	#stigAppModeLite()
	#stigCallHome()
	#stigSshd()
	#stigGuiBanner()
	#stigHttpd()
	#stigUiAdvisory()
	#stigPasswordPolicy()
	#stigSnmp()
	#stigIrule()
	stigUploadCert()
	
main()