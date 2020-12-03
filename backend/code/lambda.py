import boto3
import sys
import hashlib
import time
import secrets
import os
import json
import re
import datetime
import urllib.request
from urllib.parse import urlsplit, urlunsplit
import hmac
import hashlib

# Change BUCKET_NAME to your bucket name and
# KEY_NAME to the name of a file in the directory where you'll run the curl command.
bkt = os.environ['BUCKETNAME']
seed = os.environ['SEED']
appurl = os.environ['APPURL']
vtapikey = os.environ['VTAPIKEY']
hmacsecret = os.environ['HMACSECRET']

# Set the max object size..
maxobjectsize = 200000000

def getposturl(expiretime):
    try:
        exp=int(expiretime)
    except:
        exp=5

    s3 = boto3.client('s3')
    fields = {
            "acl": "private",
            }
    conditions = [
        {"acl": "private"},
        {"content-type":"text/plain"},
        ["content-length-range", 1, maxobjectsize],
        ["starts-with", "$x-amz-meta-tag", ""]
    ]
    
    # sha256 of seed, random bits and time just to make sure it is unique ;).
    random = seed+str(time.time())+str(secrets.randbits(256))
    h = hashlib.sha256()
    h.update(random.encode("utf-8"))
    keyname = "{exp}day/{sha256}".format(exp=exp,sha256=h.hexdigest())
    
    return s3.generate_presigned_post(Bucket=bkt,Key=keyname,Fields=fields,Conditions=conditions)


def getobj(key):
    s3 = boto3.client('s3')
    response = s3.head_object(Bucket=bkt, Key=key)

    expstr = response["Expiration"].split('"')[1].split(',')[1].strip()
    exp = datetime.datetime.strptime(expstr,'%d %b %Y %H:%M:%S %Z')  
    print (response['Expiration'])
    # When an object is expired, it is put on a queue to get deleted by AWS. 
    # This obviously might take sometimes so just incase AWS drops the ball, we will remove the file anyway.
    if (exp < datetime.datetime.now()):
        print("Object was expired, Deleting it now")
        deleteobj(key)
        return {
            "objsize": 0,
            "objname": "File removed",
            "signedurl": ""
        }
    
    objsize = response['ContentLength']
    objname = ""
    try:
        filemetadata = json.loads(response['ResponseMetadata']['HTTPHeaders']['x-amz-meta-tag'])
        objname = filemetadata["name"]
    except:
        objname = "unknown-file-name"
    return {
        "objsize":objsize,
        "objname": objname,
        "signedurl": s3.generate_presigned_url(
        'get_object',
        Params={'Bucket': bkt,
        'Key': key},
        ExpiresIn=3600
    )
    }

def deleteobj(key):
    s3 = boto3.client('s3')
    return s3.delete_object(
        Bucket=bkt,
        Key=key)

def checkvirus(filehash):
    if (vtapikey == "none"):
        return {'status_code':404}
    BASEURL = "https://www.virustotal.com/vtapi/v2/"
    VERSION = "0.0.9"
    API_KEY = vtapikey
    headers = {
            "Accept-Encoding": "identity",
            "User-Agent": f"gzip,  virustotal-python {VERSION}",
    }
    params = {"apikey": API_KEY,"resource":filehash}   
    req = urllib.request.Request(f"{BASEURL}file/report?apikey={API_KEY}&resource={filehash}", headers=headers)
    rawresponse = urllib.request.urlopen(req).read()
    resp = json.loads(rawresponse.decode("utf-8"))
    if (resp['response_code'] != 1):
        return dict(
                sha1 = filehash,
                positives = 0,
                total = 0,
                vtlink = f"https://www.virustotal.com/gui/file/{filehash}",
                detect = False,
                error = False
            )
    print (resp)
    return dict(
                sha1 = filehash,
                positives = resp['positives'],
                total = resp['total'],
                vtlink = resp['permalink'],
                detect = True if resp['positives'] > 0 else False,
                error = False
            )

# Validate timestamp using hmac
def validatetime(secret,text):
    try:
        key = secret.encode('utf-8')
        data = text.split(".")[0].encode('utf-8')
        t = int(data)
        print(text)
        if( int(time.time()) < t):
            signature = text.split(".")[1].lower()
            sig = hmac.new(key=key, msg=data, digestmod=hashlib.sha256 ).hexdigest().lower()
            print(sig)
            if signature == sig :
                return True
    except:
        pass
    return False
#https://www.serverless.com/framework/docs/providers/aws/events/apigateway/#example-lambda-proxy-event-default
def app_handler(event, context):
    print ("Starting")
    try:
        referer = event["headers"]["Referer"]
    except:
        referer = ""
    path = event["path"]
    # In prod, we will exit and return 200ok
    if (appurl != "devmode" and not referer.startswith(appurl)):
        return {
        "statusCode": 200,
        "body"  : 'ok'
    }   
    split_url = urlsplit(referer)
    clean_path = split_url.scheme+"://"+split_url.netloc 
    
    geturlmatch = re.compile("^/[0-9]day/[0-9a-fA-F]{64}$")  
    deleteurlmatch = re.compile("^/delete/[0-9]day/[0-9a-fA-F]{64}$")  
    headers = {
        'Access-Control-Allow-Origin': clean_path,
        'Content-Type': "application/json"
    }
    statuscode = 404
    body = {"status_code":404}
    if path.startswith("/gettoken/"):
        expiredurl = True
        if (hmacsecret == "none"):
            expiredurl = False
        elif (event["queryStringParameters"] != None and "exp" in event["queryStringParameters"]):
            signedtimestamp = event["queryStringParameters"]["exp"]
            if (validatetime(hmacsecret,signedtimestamp)):
                expiredurl = False
        # If hmacsecret is not set or the url is not yet expired, generate token.
        if (not expiredurl):
            # /gettoken/{1-5}
            try:
                expiretime=int(path[10])
                if (expiretime > 5): expiretime = 5
            except:
                expiretime=1
            try:
                body = getposturl(expiretime)
                statuscode = 200
            except:
                pass
        else:
            statuscode = 403
            body = {"err":"Invalid exp value"}
        
    elif (len(path)==46 and path.startswith("/sha1/")):
        try:
            body = checkvirus(path[6:])
            statuscode = 200
        except:
            pass
    elif(geturlmatch.match(path)):
        try :
            body = getobj(path[1:])
            statuscode = 200
        except:
            pass

    elif(deleteurlmatch.match(path)):
        body = deleteobj(path[8:])
        statuscode = 200
    return {
        "statusCode": statuscode,
        "headers": headers,
        "body"  : json.dumps(body)
    }  
from pprint import pprint
# Our debug main - We use this to test things locally as it's not used by lambda function.
if __name__ == '__main__':
    ### Form a POST curl request that would let me upload an image to relaysecret bucket.
    # try:
    #     expiretime=int(sys.argv[1])
    # except:
    #     expiretime=5
    # print(expiretime)
    # resp=getposturl(expiretime)
    # print (resp)
    # resp['fields']['file'] = '@{key}'.format(key="kb.jpg")
    # form_values = "  ".join(["-F {key}={value} ".format(key=key, value=value)
    #                     for key, value in resp['fields'].items()])
    # # Construct a curl command to upload an image kb.jpg file to S3 :) 
    # print('curl command: \n')
    # print('curl -v {form_values} {url}'.format(form_values=form_values, url=resp['url']))
    # print (getobj("1day/22412b21be8d50e23387b68eedb5da66ab4f2fa61f757ca12896e0133f4f1d15"))
    # print('')

    # Check Sha1 for eicar file.
    print(json.dumps(checkvirus("3395856ce81f2b7382dee72602f798b642f14140")))
    
