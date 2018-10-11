
import sys
import os
import urllib
import urllib2
import urlparse
import requests
from get import get_reflect_detect

method = ''
flag = 'q0w1e2'




def get_fuzzing(target,ck):
	print '[*]now demo test reflect xss......'
	parsed_tuple = urlparse.urlparse(urllib.unquote(target))
	url_query = urlparse.parse_qs(parsed_tuple.query,True)
	print url_query
	for i in url_query.keys():
		query = str(i) + '=' + str(url_query[i][0])
		tmp = query + flag
		location = str(url_query[i][0]) + flag
		
		now_target = target.replace(query,tmp)
		
		try:
			data = {}
			if ck != 'n' or ck != 'N':
				data = {'Cookie':ck}
			data = urllib.urlencode(data)
			req = urllib2.Request(now_target,data = data)
			res = urllib2.urlopen(req)
			content_html = res.read()
			if flag in content_html or location in content_html:
				get_reflect_detect(now_target,ck,flag)
			else:
				return False
		except:
			pass

target = raw_input('[*]please enter the url ou want to test:')
ck = raw_input('[*]please enter the cookie ; if exists , enter n/N:')
try:
	data = {}
	if ck != 'n' or ck != 'N':
		data = {'cookie':ck}
	data = urllib.urlencode(data)
	req = urllib2.Request(target,data = data)
	res = urllib2.urlopen(req)
except:
	print '[*]can not connect to target , please check'

if '=' in target:
	method = 'GET'
else:
	method = 'POST'

if method == 'GET':
	get_fuzzing(target,ck)