import datetime
import hashlib
import json
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
import base64
import random
import copy
import time

import sys
inp = sys.stdout


def freopen(filename, mode):
    if mode == "r":
        sys.stdin = open(filename, mode)

    elif mode == "w":
        sys.stdout = open(filename, mode)


# freopen("input.txt", "r") #Uncomment this code to give input from input.txt and see output in output.txt
# freopen("output.txt", "w")


############################################### RSA cryptography for Digital signature ###############################################

def key_gen():
    length = 1024
    key = RSA.generate(length, Random.new().read)

    private_key = key.publickey()
    # print((key.d))
    # print((key.e))
    encryptor = PKCS1_OAEP.new(private_key)
    decryptor = PKCS1_OAEP.new(key)
    return decryptor, encryptor


def encrypt(pr_key, text):
    encrypted = pr_key.encrypt(text.encode())
    return encrypted


def verify(public_key, data, ct):
    decrypted = public_key.decrypt(ct).decode()
   # print(decrypted, data)

    if decrypted == data:
        return 1
    return 0

############################################# Wallet class ############################################################

def hash_value(a):
    s=str(a)
    return hashlib.sha256(s.encode()).hexdigest()

class wallet:
    def __init__(self, public_key,private_key):
        self.address = hash_value(public_key)
        self.public_key=public_key
        self.private_key=private_key
        self.utxo = []
        self.utxo.append([100.0,hash_value(str(public_key))])#Intial amount in wallet

    def transact(self, amt):

        b = []
        
        for i in self.utxo:
            #print(amt,i)
            if (amt >= i[0]):
                y = i[0]
                amt -= y
            else:
                y = i[0]
                y -= amt
                amt = 0
            
        #print(amt)
            # print("rem",amt)
        if (amt == 0):
            # self.utxo=b
            return 1
        else:
            return 0

    def deduct(self, c):
        b = []
        for i in self.utxo:
            if (c >= i[0]):
                c -= i[0]
            else:
                y = i[0]
                y -= c
                c = 0
                b.append([y,i[1]])
        self.utxo = b

    def add(self,c,f):
        self.utxo.append([c,f])


######################################################## User Class ######################################################################

class user:
    def __init__(self, name, id, public_key, private_key):
        self.name = name
        self.id = id
        self.private_key = private_key
        self.public_key = public_key
        self.miner_idx = 0
        self.transactions=[]
        self.wallet = wallet(public_key,private_key)

    def print_user(self):
        print("Name:", self.name,end=" ")
        print("id:", self.id)
        print(self.wallet.utxo)

################################################ Caluclation of merkle root from transactions hash ###############################

def cal_merkleRoot(transactions):
    a = []
    for i in transactions:
        x = str(i)
        a.append(hashlib.sha256(x.encode()).hexdigest())

    while len(a) > 1:
        i = 0
        b = []
        while (i < len(a)):
            x1 = str(a[i])
            x2 = ""
            if (i+1 < len(a)):
                x2 = str(a[i+1])
                x1 += x2
                x = hashlib.sha256(x1.encode()).hexdigest()
                b.append(x)

            else:
                b.append(a[i])
            i += 2
        a = b
    return a[0]

######################################## Block Class #################################################################################

class block:
    def __init__(self, prev_hash, index, transactions):
        self.prev_hash = prev_hash
        self.index = index
        self.timestamp = str(datetime.datetime.now())
        self.nonce = 0
        self.cur_hash = 0
        self.merkle_root = cal_merkleRoot(transactions)
       # print(transactions)
        self.transactions = transactions
        self.tarnsactions_hash = []
        for x in transactions:
            self.tarnsactions_hash.append(
                (hashlib.sha256(str(x).encode()).hexdigest()))

    def mineblock(self): # Mining the block => calculating nonce
        s1 = ""
        for x in self.transactions:
            s1 += str(x)
        s = str(self.prev_hash)+self.timestamp+s1
        for i in range(0, 1000000):
            ns = s+str(i)
            hash_val = hashlib.sha256(ns.encode()).hexdigest()
            # print(hash_val[:2])

            if hash_val[:4] == "0000":
                self.cur_hash = hash_val
                self.nonce = i
                break

    def print_block(self):

        print("\n")
        print(
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        print("\n")
        print("Index:", self.index)
        print("Previous hash", self.prev_hash)
        print("Current hash", self.cur_hash)
        print("nonce", self.nonce)
        print("timestamp", self.timestamp)
        print("Merkle root", self.merkle_root)

        print("Transactions", (self.transactions))
        print("Transactions hash",self.tarnsactions_hash)
        print("\n")
        print(
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

    def print_hash(self):
        print(self.cur_hash)
        print(self.nonce)

#################################################### Miner Class #################################################################
class miner:
    def __init__(self, id):
        self.id = id
        self.chain = []
        self.transactions = []
        self.mem_pool = []
        x,y=key_gen()
        self.public_key=x
        self.private_key=y
        self.wallet=wallet(x,y)

    def add_block(self, block):
        block.mine()
        self.chain.append(block)

    def verify_block(self, b):
        if (str(b.cur_hash)[:4] != "0000"):
            return 0
        if (b.merkle_root != cal_merkleRoot(b.transactions)):
            return 0
        return 1

    # def add_transaction(self,idx1,idx2,t_id,amt):
    #     user_from=self.users[idx1]
    #     user_to=self.users[idx2]
    #     tran={"from":f"{user_from}","to":f"{user_to}","amount":amt,"transaction_id":f"{t_id}"}


################################################## Function to verify transactions #################################################

def verify_transaction(t, blockchain_instance):
    u1 = int(t["from"])-1
    u2 = int(t["to"])-1
    user2 = blockchain_instance.user_list[u2]
    user1 = blockchain_instance.user_list[u1]
    amt = float(t["amount"])+float(t["reward"])
    rwd = float(t["reward"])
    kk = str(t["from"])+str(t["to"])+str(t["amount"]) + \
        str(t["reward"])+str(t['id'])
    byte = bytes()
    if (verify(t["public_key"], kk, byte.fromhex(t["digital_signature"])) == 0):
        return 0
    if (user1.wallet.transact(amt) == 0):
        return 0

    return 1

def execute_transaction(t, blockchain_instance, miner_id):
    u1 = int(t["from"])-1
    u2 = int(t["to"])-1
    user2 = blockchain_instance.user_list[u2]
    user1 = blockchain_instance.user_list[u1]
    amt = float(t["amount"])+float(t["reward"])
    rwd = float(t["reward"])
    kk = str(t["from"])+str(t["to"])+str(t["amount"]) + \
        str(t["reward"])+str(t['id'])
    byte = bytes()
    
    user1.wallet.deduct(amt)
    user1.transactions.append(t)
    user2.wallet.add(amt-rwd,hash_value(user1.public_key))
    user2.transactions.append(t)
    blockchain_instance.miner_list[miner_id].wallet.add(rwd,hash_value(user1.public_key))
    blockchain_instance.miner_list[miner_id].transactions.append(t)

    return 1

################################# The blcokchain class ########################################################################

class blockchain:
    def __init__(self):
        self.miner_list = []
        self.chain = []
        self.user_list = []
        self.prev_trans_id = 0

    def add_user(self, user):
        self.user_list.append(user)

    def add_miner(self, miner):
        self.miner_list.append(miner)
    def proof_of_work(self,prev_hash, ind, transactions):
        cur_min=9999999999999999999999999
        j=0
        i=-1
        bk=[]
        for x in self.miner_list:
            i+=1
            new_block=block(prev_hash, ind, transactions)
            t1=time.time()
            new_block.mineblock()
            t2=time.time()
            time_elapsed=t2-t1
            if(time_elapsed<cur_min):
                cur_min=time_elapsed
                bk=new_block
                j=i
        return j,bk
            
            
            
            

############################################# The complete Pipeline ###################################################################

def sub_main():
    blockchain_instance = blockchain()
    c = 0
    for i in range(0, 10):
        c += 1
        miner_new = miner(i)
        miner_p = copy.copy(miner_new)
        miner_p.mem_pool = []
        # print(miner_p.id)

        x, y = key_gen()
        
        #print(private_pem)
        #print(x._hashObj,x._label)
        
        
        u1 = user(f"User{c}", c, x, y)
        user1 = copy.copy(u1)

        c += 1
        x, y = key_gen()
    
        u2 = user(f"User{c}", c, x, y)
        user2 = copy.copy(u2)

        # print(user2.private_key,user2.public_key)
        user1.miner_idx = i
        user2.miner_idx = i
        blockchain_instance.add_user(user1)
        blockchain_instance.add_user(user2)
        blockchain_instance.miner_list.append(miner_p)
        # print(blockchain_instance.miner_list)
    

   # print(blockchain_instance.miner_list)
    while True:
        print("0 => Print Blockchain \n1 => Enter transactions\n2 => Print the wallets of users and miners\nElse => Exit")
        a = input("Enter operation: ")
        if (a == "1"):
            
            #Taking transactions as input
            n = int(input("Enter number of transactions:"))
            
            tr = []
            for i in range(0, n):
                id1, id2, coins, reward = input().split()
                id1 = int(id1)
                id2 = int(id2)
                id1-=1
                id2-=1
                coins = float(coins)
                reward = float(reward)
                user1 = blockchain_instance.user_list[id1]
                user2 = blockchain_instance.user_list[id2]
                minerp = user1.miner_idx
                # if(blockchain_instance.isValid(id1,id2,coins,reward)):
                t = {"from": f"{user1.id}", "to": f"{user2.id}", "amount": f"{coins}",
                     "reward": f"{reward}", "id": f"{blockchain_instance.prev_trans_id}"}
                kk = str(t["from"])+str(t["to"])+str(t["amount"]) + \
                    str(t["reward"])+str(t['id'])
                data = encrypt(user1.private_key, kk)
                t["digital_signature"] = data.hex()
                t["public_key"] = user1.public_key
                # print(data)
                blockchain_instance.prev_trans_id += 1
                tr.append(t)
                # for x in blockchain_instance.miner_list:
                #     x.mem_pool.append(t)  # pushed in every mempool
                    
            if(len(tr)==0):
                print("No transactions")
                continue
            # miner_id = random.randint(0, 9) # Random selection for Miner
            # print("Miner Selected: ", miner_id)
            prev_hash = 0
            ind = 0
            if (len(blockchain_instance.chain) == 0):
                prev_hash = 0
                ind = 0
            else:
                prev_hash = blockchain_instance.chain[-1].cur_hash
                ind = blockchain_instance.chain[-1].index+1
            
            # miner_id=blockchain_instance.proof_of_work(prev_hash, ind, transactions)
            # print("Miner Selected: ", miner_id)

            transactions = copy.copy(tr)
            t1 = []
            c = 0
            
            # Transaction validation
            miner_id,new_block=blockchain_instance.proof_of_work(prev_hash, ind, transactions)
            
            print("Miner Selected: ", miner_id)
            for tx in transactions:
                c += 1
                if (verify_transaction(tx, blockchain_instance)):
                    t1.append(tx)
                    execute_transaction(tx, blockchain_instance, miner_id)
                    
                    
                    print("Transaction details: ", tx)
                else:
                    print(f"Transaction {c} invalid")
            transactions = t1
            if (len(transactions) == 0):
                print("No valid transactions")
                continue
            new_block=block(prev_hash, ind, transactions)
            new_block.mineblock()
            for x in blockchain_instance.miner_list:
                    x.mem_pool.append(transactions)  
            
            # for tx in transactions:
            #     execute_transaction(tx, blockchain_instance, miner_id)

            #new_block = block(prev_hash, ind, transactions) #New block creation
            # new_block=copy.copy(nb)
            #new_block.mineblock()
            
            # block validation
            if (blockchain_instance.miner_list[miner_id].verify_block(new_block)):

                blockchain_instance.chain.append(new_block)

                print("Block added and verified")
            else:
                print("Invalid Transaction")  # Not valid transaction

            # blockchain_instance.chain.append(new_block)
            for j in blockchain_instance.miner_list:
                j.mem_pool.clear()
                # propagating the chain
                j.chain = copy.copy(blockchain_instance.chain)
        elif a == "0":
            for x in blockchain_instance.chain:
                x.print_block()
        elif a=="2":
            for i in blockchain_instance.user_list:
                i.print_user()  
            c=-1
            for i in blockchain_instance.miner_list:
                c+=1
                print(f"Miner{c}\n",i.wallet.utxo)
        else:
            break


sub_main()

##Copyright Knightmare b19cse053