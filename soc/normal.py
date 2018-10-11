import sys
from elasticsearch import Elasticsearch
import numpy as np
import pandas as pd


def getlog(body):
    es = Elasticsearch("http://10.0.4.154:9200/")
    es_index = 'kafka-nginx-access-2018.10.02'
    doc_type = 'doc'
    result = es.search(index = es_index,doc_type = doc_type,body = body)
    total = result['hits']['total']
    log_list = []
    if total > 0:
        log_list = [hit['_source'] for hit in result['hits']['hits']]
    return log_list


def get():
    body1 = {"from":0,"size":5000,'query':{'match_all':{}}}
    url_list = []
    log_list = getlog(body1)
    for i in range(0,len(log_list)):
    	url_list.append(log_list[i])
    col = ['url']
    df = pd.DataFrame(columns = col,data = url_list)
    df.to_csv("normal.csv",index = False)

get()