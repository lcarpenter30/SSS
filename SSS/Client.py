

import requests
import json
import tempfile
import os
import re
import yaml
import rsa
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode
import OpenSSL
from Crypto.PublicKey import RSA
from base64 import b64decode
from Crypto.Util import asn1
import datetime

SESSION=""
UID = ""

from cStringIO import StringIO
url = 'https://localhost/'
#r=requests.get(url, verify="/Users/logancarpenter/PycharmProjects/SSS/root-ca/public/root.pem")
CLENTNAME=""
#CLENTID="1234"
BASE_PATH=""


# def getfile(filename):
#     f = open("filelib.json", "rb")
#     files= json.loads(f.read())
#
#     f.close()
#     if filename not in files.keys():
#         return "FAIL"
#     else:
#         return files[filename]
#
# def savefile(filename):
#     filelib = open("filelib.json", "rb")
#     nf = json.dumps(filelib)
#     f = open("filelib.json","w")
#     f.write(json)
#     f.close()
def checkFileIn(FileName,flag,filePath,CLENTID):
    with open(filePath, 'rb') as upload:
        data = {'FileName': FileName, 'Flag': flag, 'ClientID': CLENTID,"SessionKey":SESSION}
        # tmp = open("tmp.txt", "w")
        # tmp.write(str(data))
        # tmp.close()
        # tmp = open("tmp.txt", "rb")
        new_file, filename = tempfile.mkstemp()
        print(filename)
        os.write(new_file, "")
        f=open(filename, 'w')
        json.dump(data,f)
        f = open(filename, 'rb')

        response = requests.post(url+"checkin", json=data,verify="/Users/logancarpenter/PycharmProjects/SSS/root-ca/public/root.pem", files={'file': upload,'data':f})
    return response.content

    #response = requests.post(url+"checkin", json=data,verify="/Users/logancarpenter/PycharmProjects/SSS/root-ca/public/root.pem")
    #print response.content

        #r = requests.post(url + "checkin", json=data,verify="/Users/logancarpenter/PycharmProjects/SSS/root-ca/public/root.pem")
def login (CLENTID, password):
    global SESSION
    data = {'ClientID': CLENTID,"Password":password}
    response = requests.post(url + "login", json=data,verify="/Users/logancarpenter/PycharmProjects/SSS/root-ca/public/root.pem")

    if "FAIL" not in response.content:
        SESSION = response.content
        print SESSION
    else:
        print response.content
        print "Login Failed"
        #quit()

def register_user(CLENTID, password):
    data = {'ClientID': CLENTID,"Password":password}
    response=requests.post(url+"register", json=data,verify="/Users/logancarpenter/PycharmProjects/SSS/root-ca/public/root.pem")
    print response.content

def search(CLENTID,search,SessionKey):
    data = {'ClientID': CLENTID, "Search": search,"SessionKey":SessionKey}
    response = requests.post(url + "search", json=data,
                             verify="/Users/logancarpenter/PycharmProjects/SSS/root-ca/public/root.pem")
    data = json.loads(response.content)
    if "files" in data.keys():
        for p in data['files']:
            print('Filename: ' + p['FILENAME'])
            print('Owner: ' + p['OWNER'])
            print('DID: ' + p['DID'])
            print('')
    else:
        print "NO RESULTS"
def safeDel(userid,FileName):
    data = {'FileName': FileName, 'ClientID':userid}
    response = requests.post(url+"delete", json=data,verify="/Users/logancarpenter/PycharmProjects/SSS/root-ca/public/root.pem")
    return response.content

def checkout(CLENTID,SessionKey,FileName):
    data = {'FileName': FileName, 'SessionKey': SessionKey, 'ClientID': CLENTID}
    r=requests.post(url+"checkout", json=data,verify="/Users/logancarpenter/PycharmProjects/SSS/root-ca/public/root.pem")

    if r.content =="LOGIN REQUIRED":
        print r.content
    else:
        if "Error" in r.content:
            print "FAIL TO DO CHECKOUT"
            print r.content
            return
        print r.content
        print r.headers
        d = r.headers['content-disposition']
        filename = re.findall("filename=(.+)", d)[0]
        with open(filename, 'wb') as f:
            f.write(r.content)
            f.close()
        #print "<<<<<<<<<<<<<<<<<<<<<<<file contnet is   ", r.content
        #print ">>>>>>>>>>>>>>>"

def logout(uname):
    data = {'ClientID': uname}
    response = requests.post(url + "logout", json=data,
                             verify="/Users/logancarpenter/PycharmProjects/SSS/root-ca/public/root.pem")
    print response.content
def delegation(clientID,filename,addpermissionID,time,pfString):
    data = {'ClientID': clientID,'Time':time ,'FileName':filename,"AddPermissionTo":addpermissionID,"PropFlags":pfString}
    response = requests.post(url + "delegation", json=data,verify="/Users/logancarpenter/PycharmProjects/SSS/root-ca/public/root.pem")
    print response.content



#print(r.text)
#register_user("Logan")
#checkFileIn("key.priv","CONFIDENTIAL","/Users/logancarpenter/PycharmProjects/SSS/key.priv","Logan")

#ciphertext= encrypt_RSA("Server/key.pub","Hello")
#print decrypt_RSA("Server/server.key",ciphertext)


#
#requests.post(url + "TEST",verify="/Users/logancarpenter/PycharmProjects/SSS/root-ca/public/root.pem")

if __name__ == "__main__":
    while True:
        function = raw_input("Function: ")
        if function == "reg":
            UID = raw_input("name: ")
            password = raw_input("password: ")
            register_user(UID, password)
        elif function == "login":
            UID = raw_input("name: ")
            password = raw_input("password: ")
            login(UID, password)
        elif function == "CheckIn":
            did = raw_input("DID: ")
            flag = raw_input("Flag: ")
            path = raw_input("File path: ")
            fid = checkFileIn(did, flag, path, UID)
            print "FID ", fid
        elif function == "CheckOut":
            did = raw_input("DID: ")
            checkout(UID, SESSION, did)
        elif function == "Delegation":
            did = raw_input("DID: ")
            targetUser = raw_input("Target User: ")
            time = raw_input("Time:")
            permit = raw_input("Permit (e.g. \"rm, in, out\"): ")
            delegation(UID, did, targetUser, time, permit)
        elif function == "Delete":
            FileName=raw_input("FileName:")
            safeDel(UID, FileName)
        elif function=="SetName":
            UID = raw_input("name: ")
        elif function == "LogOut":
            if UID:
                logout(UID)
            else:
                UID = raw_input("name: ")
                logout(UID)
        elif function=="search":
            FileName = raw_input("FileName:")
            search(UID,FileName,SESSION)



'''
#register_user("logan","password")
#register_user("sd","password")
login("sd","password")
fid=checkFileIn("key.priv","NONE","/Users/logancarpenter/PycharmProjects/SSS/key.priv","sd")
checkout("sd","",fid)
fid=checkFileIn(fid,"NONE","/Users/logancarpenter/PycharmProjects/SSS/key.pub","sd")
checkout("sd","",fid)
#delegation("sd",fid,"logan","52,0,0,0","rm, in")
#login("logan","password")
#checkout("logan","",fid)
#raw_input()
#logout("sd")
#logout'''