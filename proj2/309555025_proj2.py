#!/usr/bin/env python
# coding: utf-8

# In[2]:


import json
import numpy as np
import random
import os
import sys
#
from sklearn.datasets import load_iris
from sklearn import tree
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report


# In[27]:


def check_score(data):
    zero = 0
    one = 0
    for d in data:
        if(d[0] == 0):
            zero += 1
        else:
            one += 1
    if(zero > one):
        return 0
    else:
        return 1
def check_src_IP(data):
    srcIP_set = set()
    for d in data:
        srcIP_set.add(d[1])
    if(len(srcIP_set) < len(data)*0.2):
        return 0
    else:
        return 1
def check_src_port(data):
    srcPort_set = set()
    for d in data:
        srcPort_set.add(d[2])
    if(len(srcPort_set) < len(data)*0.2):
        return 0
    else:
        return 1

def check_dest_IP(data):
    destIP_set = set()
    for d in data:
        destIP_set.add(d[3])
    if(len(destIP_set) < len(data)*0.2):
        return 0
    else:
        return 1

def check_dest_port(data):
    destPort_set = set()
    for d in data:
        destPort_set.add(d[4])
    if(len(destPort_set) < len(data)*0.2):
        return 0
    else:
        return 1
def make_data(data,label):
    new_data = []
    for d in data:
        features = []
        features.append(check_score(d))
        features.append(check_src_IP(d))
        features.append(check_src_port(d))
        features.append(check_dest_IP(d))
        features.append(check_dest_port(d))
        features.append(label)
        new_data.append(features)
    return new_data
def make_features(data):
    new_data = []
    for d in data:
        features = []
        features.append(check_score(d))
        features.append(check_src_IP(d))
        features.append(check_src_port(d))
        features.append(check_dest_IP(d))
        features.append(check_dest_port(d))
        new_data.append(features)
    return new_data
def predict_result(predict):
    cnt_list = [0,0,0,0,0]
    for p in predict:
        cnt_list[p] += 1
    idx = cnt_list.index(max(cnt_list))
    if(idx == 0):
        return 'IP Scan'
    elif(idx == 1):
        return 'Port Scan'
    elif(idx == 2):
        return 'DDoS'
    elif(idx == 3):
        return 'RDP Brute-Force'
    else:
        return 'C&C'


# In[4]:


#
# Read all training data
#
print("--- Reading training data ---")
SAMPLES_NUM = 100
TEST_SIZE = 0.3
dir_name = './Logs/train'
file_name = ['IP_scan.json','port_scan.json','DDoS.json','RDP_bruteforce.json','C&C.json']
train_data = []
test_data = []
for fn in range(5):  
    # read data from file
    file_path = os.path.join(dir_name,file_name[fn])
    file = open(file_path,'r',encoding='utf-8')
    data = []
    for line in file.readlines():
        l = []
        json_data = json.loads(line)
        try:
            l.append(json_data['_score'])
            l.append(json_data['_source']["source"]["ip"])
            l.append(json_data['_source']["source"]["port"])
            l.append(json_data['_source']["destination"]["ip"])
            l.append(json_data['_source']["destination"]["port"])
        except Exception as e:
            continue
        data.append(l)
    file.close()
    # make features/labels
    num_list = [i for i in range(len(data))]
    random.shuffle(num_list)
    sample_data = []
    #for i in range(len(data)//SAMPLES_NUM):
    for i in range(50):
        sample_data.append([data[n] for n in num_list[i*SAMPLES_NUM:(i+1)*SAMPLES_NUM]])
    result = make_data(sample_data,fn)
    
    end = int(len(result)*TEST_SIZE)
    train_data.extend(result[:-end])
    test_data.extend(result[-end:])
    print("File:",file_name[fn],"ok")


# In[5]:


#
# Build decision tree model
#
print("--- Building decision tree model ---")
random.shuffle(train_data)
random.shuffle(test_data)
train_data = np.array(train_data)
test_data = np.array(test_data)

train_X = train_data[:,:-1]
train_y = train_data[:,-1]
test_X = test_data[:,:-1]
test_y = test_data[:,-1]

# 建立分類器
clf = tree.DecisionTreeClassifier()
ca_clf = clf.fit(train_X, train_y)

# 預測
predict_y = ca_clf.predict(test_X)

#
print(classification_report(test_y,predict_y))


#
# Read target data
#
print("--- Making prediction ---")
SAMPLES_NUM = 100
#dir_name = './Logs/test'
dir_name = sys.argv[1]
file_list = os.listdir(dir_name)
#
for file_name in file_list:
    # read data from file
    file_path = os.path.join(dir_name,file_name)
    file = open(file_path,'r',encoding='utf-8')
    data = []
    for line in file.readlines():
        l = []
        json_data = json.loads(line)
        try:
            l.append(json_data['_score'])
            l.append(json_data['_source']["source"]["ip"])
            l.append(json_data['_source']["source"]["port"])
            l.append(json_data['_source']["destination"]["ip"])
            l.append(json_data['_source']["destination"]["port"])
        except Exception as e:
            continue
        data.append(l)
    file.close()
    # make features/labels
    num_list = [i for i in range(len(data))]
    random.shuffle(num_list)
    sample_data = []
    for i in range(len(data)//SAMPLES_NUM):
        sample_data.append([data[n] for n in num_list[i*SAMPLES_NUM:(i+1)*SAMPLES_NUM]])
    target = make_features(sample_data)
    predict = ca_clf.predict(target)
    print(file_name,": ",predict_result(predict),sep='')


# In[ ]:




