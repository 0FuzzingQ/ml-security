
import sys
import os
import urllib
import urllib2
import urlparse
import requests
from payload import load
import webbrowser
import time



def get_reflect_detect(target,ck,flag):
	payload = load()
	for i in range(0,len(payload)):
		exp = flag + str(payload[i])
		now_target = target.replace(flag,exp)
		#print now_target
		try:
			data = {}
			if ck != 'n' and ck != 'N':
				data = {'Cookie':ck}
			data = urllib.urlencode(data)
			req = urllib2.Request(now_target,data = data)
			res = urllib2.urlopen(req)
			content_html = res.read()
			#print content_html
			if exp in content_html or str(payload[i]) in content_html:
				#print 'aaa'
				webbrowser.open(now_target)
				exit()
		except:
			pass
	

