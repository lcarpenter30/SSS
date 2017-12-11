from flask import Flask,request,make_response
import json
import requests
import os
import shelve
import hashlib
from cryptography.fernet import Fernet
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from base64 import b64decode
import uuid

import uuid, M2Crypto

import rsa
from binascii import hexlify
import OpenSSL
import datetime
import hmac


app = Flask(__name__)
BASE_PATH= os.path.dirname(os.path.realpath(__file__))
public_key_loc ="/Users/logancarpenter/PycharmProjects/SSS/Server/key.pub"
private_key_loc="/Users/logancarpenter/PycharmProjects/SSS/Server/mykey.pem"
Sessionkeys={}
class UserInfo:
    file_ids = set({})
    uid = ''
    file_path = '' #__file__/uid
    password=""
    def __init__(self, name):
        self.uid = name

class FileInfo: #this is the file metadata
    fid=""
    filename = ""
    integrity=False
    confidential=False
    uid=""
    filepath=""
    key = ""
    sign = ""
    delegate_infos = {} #usd, time
    rights = {} #uid proflag set [rm, in, out]

    def __init__(self, fid, integrity, confidential, uid, filepath, key, sign, filename):
        self.filename = filename
        self.fid = fid
        self.integrity = integrity
        self.confidential = confidential
        self.uid = uid
        self.filepath = filepath
        self.key = key
        self.sign = sign

    def __str__(self):
        return ("filename  " + self.filename + "  fid  " + self.fid + " integrity " +  str(self.integrity) + "  confidential  " +
                str(self.
                confidential) + "  owner  " +  self.uid + "  filepath  " +  self.filepath + "  delegate infos  " + str( self.delegate_infos) + "  key  " +  self.key)


def matchssesion(Skey,client_id):
    print Sessionkeys.keys()
    print client_id, "  client   !!!!!!!!!"
    if client_id in Sessionkeys.keys():
        return True
        #if Skey==Sessionkeys[client_id]:
        #    return True
        #else:
        #    return False

    else:
        return False



@app.route("/logout",methods = ['POST'])
def closeSession():
    data = request.get_json()
    client_id = data["ClientID"]
    global Sessionkeys
    if client_id in Sessionkeys.keys():
        del Sessionkeys[client_id]
        return "Session ClOSED"

def str_to_bool(s):
    if s == 'True':
         return True
    elif s == 'False':
         return False
    else:
         raise ValueError



@app.route("/login",methods = ['POST'])
def login():
    data = request.get_json()
    client_id = data["ClientID"]
    userkey = data["Password"]
    users_db = shelve.open("users")
    user_info = users_db[client_id]
    storedkey = "password"
    global Sessionkeys
    print " storedkey "+storedkey+" userkey "+userkey
    if storedkey == userkey:#FIX

        if client_id not in Sessionkeys.keys():
            sessionkey=str(uuid.uuid4())
            Sessionkeys[client_id]=sessionkey

            return sessionkey
        else:
            return "FAILED: Client logged in"


    else:
        return "FAILED: Authintication failure"


@app.route("/checkin",methods = ['POST'])
def checkFileIn():#change this to the pdf function name
    #data= request.get_json()

    authorized = False
    rewrite = False
    delegated = False
    integrity = False
    confidential = False

    jstr=request.files['data'].read()
    data = json.loads(jstr)
    filename = data["FileName"]
    flag = data["Flag"]
    if flag == "INTEGRITY":
        integrity = True
    if flag == "CONFIDENTIAL": # SPELL WORNG!
        confidential = True
    client_id = data["ClientID"]
    Skey = data["SessionKey"]
    #print "!!fffff  " , data["Data"]
    if not matchssesion(Skey,client_id):
        return "LOGIN REQUIRED"


    #base_path/files/user_id/+filename
    file = request.files['file']
    print ">>>file    !!! ", str(request.files['file'])

    if file:
        file_content = file.read() ###

    key = ""
    sign = ""
    users_db = shelve.open("users")
    user_info = users_db[client_id]
    file_id = filename
    print " >>>>>>>  file content ", file_content,"  filename   ", filename,"    file id   ", file_id, "<<<<<<<<"
    files_db = shelve.open("files")
    if confidential:
        print "ENCRYPT  ", key
        file_content, key = confi_content(file_content)
    if integrity:
        sign = inte_content(file_content)
    print files_db.keys()
    print "!!!!! id  ", files_db.keys()
    if not file_id in files_db.keys():
        file_id = hashlib.sha1(client_id + filename).hexdigest()
        #print "lalalal !!!!"
        print "New File: "+ filename + " Owner: " + client_id
        authorized = True
        user_path = user_info.file_path
        file_path = os.path.join(user_path, filename)
        file = open(file_path, "w+")
        print "<<<<  OVERWRITE FILE   ", file_content
        file.write(file_content)
        file.close()
        file_info = FileInfo(file_id, integrity, confidential, client_id, file_path, key, sign, filename)
        files_db[file_id] = file_info
    else:
        file_info = files_db[file_id]
        file_path = file_info.filepath
        if file_info.uid == client_id:
            rewrite = True
            authorized = True
        else:
            for del_uid in file_info.delegate_infos.keys():
                permit_time = file_info.delegate_infos[del_uid]
                now = datetime.datetime.now()
                if now < permit_time and ("in" in file_info.rights[client_id]):
                    delegated = True
                    print ("file delegation set !")
                    break
            if not delegated:
                rewrite = True
                authorized = True
    if authorized or delegated:
        file = open(file_path, "w+")
        file_info.key = key
        file_info.sign = sign
        files_db[file_id] = file_info
        file.write(file_content)
        file.close()
        file_info = files_db[file_id]
        if rewrite and not delegated:
            print "original meta file  ",  str(file_info)
            file_info = FileInfo(file_id, integrity, confidential, client_id, file_path, key, sign, filename)
            files_db[file_id] = file_info

    users_db[client_id] = user_info
    print "<<<< file path ", file_path
    print " <<<   file_id  ", file_id
    return file_id


@app.route("/delete", methods=['POST'])
def safe_delete():
    print "delete"
    AUTH=False
    data = request.get_json()
    userid =str(data.get("ClientID"))
    filename=str(data.get("FileName"))
    file_db = shelve.open("files")
    file_info = file_db[filename]
    fileowner=file_info.uid
    delegates=file_info.delegate_infos
    file_info.rights

    print userid, "  file owner   ", fileowner
    if userid == fileowner:
        AUTH=True

    for del_uid in delegates.keys():
        permit_time = delegates[del_uid]
        now= datetime.datetime.now()
        if del_uid == userid and ("rm" in file_info.rights[userid]) and now < permit_time:
            AUTH = True
    if not AUTH:
        print "NO AUTH"
        return "Error: DO NOT HAVE AUTH"
    os.remove(file_info.filepath)
    del file_db[filename]
    print "DELETE SUCCESSFUL"
    return "DELETE SUCCESFUL"


def encrypt_RSA(public_key_loc, message):
    key = open(public_key_loc, "r").read()
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)
    encrypted = rsakey.encrypt(message)
    return encrypted.encode('base64')

def decrypt_RSA(private_key_loc, package):
    print "DECRYPT  Cipher   ", package
    key = open(private_key_loc, "r").read()
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)
    decrypted = rsakey.decrypt(b64decode(package))
    print "DECRYPT  Key  ", decrypted
    return decrypted



def confi_content(content):
    key = Fernet.generate_key()
    print "encrypt with  ", key
    f = Fernet(key)
    token = f.encrypt(content)
    #cipher = encrypt_RSA(public_key_loc,key)
    #print "encrypt cipher  ", cipher
    return token, key

def inte_content(data):
    '''digest = SHA256.new()
    digest.update(content)

    with open (private_key_loc,"rb") as keyfile:
        key=keyfile.read()
    signer=PKCS1_v1_5.new(key)
    signature =signer.sign(digest)
    return signature'''
    pub_key = open(public_key_loc, "r").read()
    pub_key = hashlib.sha224(pub_key).hexdigest()
    print "SIGN KEY  IS ", pub_key
    #print " key  is   ", key
    digest_maker = hmac.new(pub_key)
    digest_maker.update(data)
    digest = digest_maker.hexdigest()
    print "SIGNATURE ---   ", digest
    return digest



def verfify_sign(public_key_loc, signature, data):
    pub_key = open(public_key_loc, "r").read()
    '''rsakey = RSA.importKey(pub_key)
    signer = PKCS1_v1_5.new(rsakey)
    digest = SHA256.new()
    # Assumes the data is base64 encoded to begin with
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += b'=' * (4 - missing_padding)
    print len(data)
    digest.update(data)
    if signer.verify(digest, b64decode(signature)):
        return True
    return False
    '''
    pub_key = hashlib.sha224(pub_key).hexdigest()
    print " key  is   ", pub_key
    digest_maker = hmac.new(pub_key)
    digest_maker.update(data)
    digest = digest_maker.hexdigest()
    print "SIGNATURE ---   ", digest
    print "ORG SIGNATRUE --- ", signature
    return digest == signature




def get_pubkey(key):
    with open(os.path.join(BASE_PATH, key), "rb") as f:
        pubkey = f.read()
        pubkey = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pubkey)
    return pubkey





@app.route("/checkout",methods = ['POST'])
def checkFileOut():#change this to the pdf function name
    data = request.get_json()
    client_id=str(data.get("ClientID"))
    file_id=str(data.get("FileName")) #This is acturally file ID
    Skey = str(data.get("SessionKey"))


    if not matchssesion(Skey,client_id):
        return "Error: LOGIN REQUIRED"
    authorized = False
    file_db = shelve.open("files")
    print "  id  !!!!!!  ", file_id
    if not file_db.has_key(file_id):
        return "Error: FILE NOT EXISTS!!!"
    file_info = file_db[file_id]
    print "<<<< delegation!*** ", file_info.delegate_infos.keys()

    if client_id == file_info.uid:
        authorized = True
    print "!!!!  ", file_info.delegate_infos
    for del_uid in file_info.delegate_infos.keys():
        permit_time = file_info.delegate_infos[del_uid]
        now = datetime.datetime.now()
        #print ">>>>  right is  ", str(file_info.rights[client_id])
        if del_uid == client_id and ("out" in file_info.rights[client_id]) and now < permit_time: #this condition may need to add propagation right
            authorized = True

    if not authorized:
        return "Error: NOT AUTHORIZED!"

    with open(file_info.filepath, "rb") as file:
        content = file.read()
    if file_info.confidential:
        print "file is confidential, dectrypt then send"
        #print "<<< content before decrypt  ", content
        #key = decrypt_RSA(private_key_loc, file_info.key)
        print "<< key ******* ", file_info.key
        f = Fernet(file_info.key)
        content = f.decrypt(content)
        print "<<< content after decrypt   ", content
    if file_info.integrity:
        print "integrity signature verify"
        if not verfify_sign(public_key_loc, file_info.sign, content):
            return "Error: SIGNATRUE IS NOT MATCH"

    response = make_response(content)
    response.headers["Content-Disposition"] = "attachment; filename={0}".format(file_info.filename)
    return response


    if not reqFile:
        print "File "+filename+" does not exist"
        return "File "+filename+" does not exist"


@app.route("/delegation", methods=['POST'])
def delegate():
    AUTH=False

    data = request.get_json()
    user_name = str(data.get("ClientID"))
    addtime=str(data.get("Time"))
    fmt=int(addtime)
    filename=str(data.get("FileName"))
    addpermissionID=str(data.get("AddPermissionTo"))
    pfString=str(data.get("PropFlags"))

    Skey = str(data.get("SessionKey"))
    if not matchssesion(Skey,user_name):
        return "LOGIN REQUIRED"
    #

    #
    file_db = shelve.open("files")
    if filename not in file_db.keys():
        return "Fail: NOT EXSITS"
    file_info = file_db[filename]
    fileowner=file_info.uid

    if user_name ==  fileowner:
        AUTH=True

    if user_name in file_info.delegate_infos.keys():
        now= datetime.datetime.now()
        deadline=file_info.delegate_infos[user_name]
        if now < deadline:
            AUTH=True
    if not AUTH:
        return "ACCESS DENIED"

    if addpermissionID == "ALL":
        #fmt=map(int,addtime.split(','))
        time= datetime.datetime.now()
        accessDeadline=time + datetime.timedelta(seconds=fmt)
        #weeks=fmt[0],days=fmt[1],hours=fmt[2],minutes=fmt[3]

        for key in file_info.delegate_infos.keys():
            file_info.delegate_infos[key] = accessDeadline
            file_info.rights[key]= pfString
            file_db[filename] = file_info
    else:

        #fmt=map(int,addtime.split(','))
        time= datetime.datetime.now()
        accessDeadline=time + datetime.timedelta(seconds=fmt)
        file_info.delegate_infos[addpermissionID]=accessDeadline
        file_info.rights[addpermissionID]= pfString
        file_db[filename] = file_info

    file_db.close()
    print "DELEGATION SUCCESSFUL"
    return "DELEGATION SUCCESSFUL"






@app.route("/register", methods=['POST'])
def register_user():#change function name
    data = request.get_json()
    user_name = str(data.get("ClientID"))
    password = str(data.get("Password"))
    if user_name=="" or password=="":
        return "Error: CHECK FILES"

    users_db = shelve.open("users")
    if users_db.has_key(user_name):
        print "Error: User already exist!"
        return "Error: User already exist!"

    user_info = UserInfo(user_name)
    user_path = os.path.join(BASE_PATH, user_name)
    os.makedirs(user_path)
    user_info.file_path = user_path
    users_db[user_name] = user_info
    #user_info.password ="password" #MAY FIX IT latter
    users_db.close()
    print "New User "+user_name+" Registered."
    return "New User "+user_name+" Registered."

@app.route("/TEST", methods=['POST'])
def test():#change function name
    print "TEST"
    print verfify_sign(public_key_loc, inte_content("bdsfjsjlkjklsdkjf"), "NASJDSBDAJSD")
    return "ok"

if __name__ == "__main__":
    app.run(host='127.0.0.1',port='443',ssl_context=('server.pem', 'server.key'))






@app.route("/register", methods=['POST'])
def register_user():#change function name
    data = request.get_json()
    user_name = str(data.get("ClientID"))
    users_db = shelve.open("users")
    if users_db.has_key(user_name):
        print "Error: User already exist!"
        return "Error: User already exist!"
    user_info = UserInfo(user_name)
    user_path = os.path.join(BASE_PATH, user_name)
    os.makedirs(user_path)
    user_info.file_path = user_path
    users_db[user_name] = user_info
    users_db.close()
    print "New User "+user_name+" Registered."
    return "New User "+user_name+" Registered."


if __name__ == "__main__":
    app.run(host='127.0.0.1',port='443',ssl_context=('server.pem', 'server.key'))




