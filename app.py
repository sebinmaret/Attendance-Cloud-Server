from flask import Flask,request,jsonify
import pymongo
import json
from phe import paillier
import pickle
import numpy as np


myclient=pymongo.MongoClient("mongodb://guest:guest@127.0.0.1:27017/mongodb")
mydb=myclient["mongodb"]
mycol=mydb["test2"]

app=Flask(__name__)

pub_key=None
pvt_key=None

#argument
# entry: {"enc_x2":[...],"x-b":[...],"enc_b":[...],"enc_tid":"xyz"}
#{"enc_x2":[1,2,3,4,5],"x_b":[0,2,3,4,1],"enc_b":[5,4,3,2,1],"enc_tid":"xyz"}
def storeEntry(enc_x2,x_b,enc_b,enc_tid):
    entry={"enc_x2":enc_x2,"x_b":x_b,"enc_b":enc_b,"enc_tid":enc_tid}
    ret=mycol.insert_one(entry)
    return ret.acknowledged

def getEntries():
    temp=list(mycol.find())
    return temp



@app.route("/api/enroll",methods=['POST'])
def enroll():
    enc_entry=request.get_data()
    enc_entry=enc_entry.decode()
    json_decoder=json.JSONDecoder()
    data=json_decoder.decode(enc_entry)
    
    #for k in ["enc_x2","enc_b","x_b"]:
    #    for i in range(len(data[k])):
    #        data[k][i]=paillier.EncryptedNumber(pub_key, int(data[k][i]))
    #        data[k][i]=pvt_key.decrypt(data[k][i]) 

    #data contains the dictionary
    ret=storeEntry(data["enc_x2"],data["x_b"],data["enc_b"],data["enc_tid"])
    return str(ret)

@app.route("/api/show",methods=['GET'])
def show():
    return str(getEntries())


@app.route("/api/verify",methods=['POST','GET'])
def verify():
    enc_entry=request.get_data()
    enc_entry=enc_entry.decode()
    json_decoder=json.JSONDecoder()
    data=json_decoder.decode(enc_entry)

    for k in ["enc_y2","enc_c"]:
        for i in range(len(data[k])):
            data[k][i]=paillier.EncryptedNumber(pub_key, int(data[k][i]))
            
    enc_y2=data["enc_y2"]
    y_c=data["y_c"]
    enc_c=data["enc_c"]

    entries=getEntries()

    result={}

    for entry in entries:
        #getting objects
        for k in ["enc_x2","enc_b"]:
            for i in range(len(entry[k])):
                entry[k][i]=paillier.EncryptedNumber(pub_key,int(entry[k][i]))

        #entry["enc_tid"]=paillier.EncryptedNumber(pub_key,int(entry["enc_tid"]))
        
        
        enc_x2=entry["enc_x2"]
        x_b=entry["x_b"]
        enc_b=entry["enc_b"]
        #enc_tid=np.array(entry["enc_tid"])

        #squared_sum
        squared_sum=sum(enc_x2)+sum(enc_y2)
        
        #multiply terms
        multiply_term1=[2*a*b for a,b in zip(x_b,y_c)]
               
        for i in range(len(multiply_term1)):
            multiply_term1[i]=pub_key.encrypt(multiply_term1[i])

        
        multiply_term2=[2*a*b for a,b in zip(enc_b, (y_c))]
        multiply_term3=[2*a*b for a,b in zip(enc_c, (x_b))]
        
        multiply_terms=[a+b+c for a,b,c in zip(multiply_term1, multiply_term2, multiply_term3)] 
        
        #result
        enc_result= squared_sum - sum(multiply_terms)
        result[entry["enc_tid"]]=str(enc_result.ciphertext())

    return jsonify(result)
        
               


if __name__=="__main__":
    #storeEntry([1,2,3,4,5],[0,2,3,4,1],[5,4,3,2,1],"xyz")
    #getEntries()
    f=open("pub_key.dat","rb")
    pub_key=pickle.load(f)
    f.close()
    f=open("pvt_key.dat","rb")
    pvt_key=pickle.load(f)
    f.close()
    app.run(host='0.0.0.0',port=3000,debug=True)
    
