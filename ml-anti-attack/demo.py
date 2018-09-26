# -*- coding:UTF-8 -*-

import os
import sys
import pyspark
from pyspark import SparkContext
from pyspark import SparkConf
from elasticsearch import Elasticsearch
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import math
import time
import urllib
import urllib2
import urlparse
import datetime
from sklearn import preprocessing
import sklearn
from sklearn import cross_validation
from sklearn.linear_model import LogisticRegression

def getlog(body):
    es = Elasticsearch("http://10.0.4.154:9200/")
    es_index = 'kafka-nginx-access-2018.09.13'
    doc_type = 'doc'
    result = es.search(index = es_index,doc_type = doc_type,body = body)
    total = result['hits']['total']
    log_list = []
    if total > 0:
        log_list = [hit['_source'] for hit in result['hits']['hits']]
    return log_list

def getvector(log):
    vect_list = []

    if int(log['http_status']) == 403:
        vect_list.append(1)
    else:
        vect_list.append(0)

    #url长度
    url = log['url'].lower()
    url_len = len(url)
    vect_list.append(url_len)

    #熵
    tmp_dict = {}
    for i in range(0,url_len):
        if url[i] in tmp_dict.keys():
            tmp_dict[url[i]] = tmp_dict[url[i]] + 1
        else:
            tmp_dict[url[i]] = 1
    shannon = 0
    for i in tmp_dict.keys():
        p = float(tmp_dict[i]) / url_len
        shannon = shannon - p * math.log(p,2)
    vect_list.append(shannon)

    #参数长度
    parsed_tuple = urlparse.urlparse(urllib.unquote(url))
    url_query = urlparse.parse_qs(parsed_tuple.query,True)

    url_first_arg_len = 0
    if len(url_query) == 0:
        url_first_arg_len = 0
    elif len(url_query) == 1:
        url_first_arg_len = len(url_query[url_query.keys()[0]][0])
    else:
        max_len = 0
        for i in url_query.keys():
            if len(url_query[i][0]) > max_len:
                max_len = len(url_query[i][0])
        url_first_arg_len = max_len
    vect_list.append(url_first_arg_len)
    #print url,url_first_arg_len

    #注入，跨站，执行，文件类恶意字符出现次数
	#lower = urllib.unquote(url)
    lower = url
    url_ilg_sql = lower.count('select')+lower.count('and')+lower.count('or')+lower.count('insert')+lower.count('update')+lower.count('sleep')+lower.count('benchmark')+\
		lower.count('drop')+lower.count('case')+lower.count('when')+lower.count('like')+lower.count('schema')+lower.count('&&')+lower.count('^')+lower.count('*')+lower.count('--')+lower.count('!')+lower.count('null') +\
        lower.count('%')+lower.count(' ')
    url_ilg_xss = lower.count('script')+lower.count('>')+lower.count('<')+lower.count('&#')+lower.count('chr')+lower.count('fromcharcode')+lower.count(':url')+\
		lower.count('iframe')+lower.count('div')+lower.count('onmousemove')+lower.count('onmouseenter')+lower.count('onmouseover')+lower.count('onload')+lower.count('onclick')+lower.count('onerror')+lower.count('#')+lower.count('expression')+lower.count('eval')
    url_ilg_file = lower.count('./')+lower.count('file_get_contents')+lower.count('file_put_contents')+lower.count('load_file')+lower.count('include')+lower.count('require')+lower.count('open')
    vect_list.append(url_ilg_sql + url_ilg_xss + url_ilg_file)
	#vect_list.append(url_ilg_xss)
	#vect_list.append(url_ilg_file)

    #cookie uid

    #print vect_list
    return np.array(vect_list)

if __name__ == '__main__':
    body1 = {"from":0,"size":10000,'query':{'match_all':{}}}
    log_list = getlog(body1)

    tmp = {}
    i = 0
    for i in range(0,len(log_list)):
        if int(log_list[i]['http_status']) :
            if log_list[i]['client_ip'] not in tmp.keys():
                tmp[log_list[i]['client_ip']] = str(log_list[i]['@timestamp']) + '|'
            else:
                tmp[log_list[i]['client_ip']] = tmp[log_list[i]['client_ip']] + str(log_list[i]['@timestamp']) + '|'

    #构建特征矩阵

	vector = []
	vector_list = []
    for i in range(0,len(log_list)):
        #print log_list[i]
        vector_list.append(getvector(log_list[i]))
    vector = np.vstack((x for x in vector_list))
    x = vector_list
    df = pd.DataFrame(x,columns = ['label','len','shannon','first','url_danger'])


    train = df
    y_train = train.values[:,0]

    scaler = preprocessing.StandardScaler()
    len_scaler_param = scaler.fit(train['len'].values.reshape(-1,1))
    train['len_scaled'] = scaler.fit_transform(train['len'].values.reshape(-1,1),len_scaler_param)
    shan_scaler_param = scaler.fit(train['shannon'].values.reshape(-1,1))
    train['shan_scaled'] = scaler.fit_transform(train['shannon'].values.reshape(-1,1),shan_scaler_param)
    first_scaler_param = scaler.fit(train['first'].values.reshape(-1,1))
    train['first_scaled'] = scaler.fit_transform(train['first'].values.reshape(-1,1),first_scaler_param)

    x_train = train.filter(regex = 'first_scaled|shan_scaled|len_scaled|url_danger')
    print x_train.head(5)

    x_train = x_train.as_matrix()
    lr = LogisticRegression().fit(x_train,y_train)
    model = cross_validation.cross_val_score(lr,x_train,y_train,n_jobs = -1,cv = 5)
    print model
