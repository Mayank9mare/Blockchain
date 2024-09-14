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
import sqlite3
import ast
from ecdsa import SigningKey,VerifyingKey

import sys
inp = sys.stdout
con = sqlite3.connect("tutorial.db")

def run_sql(query):
    cur = con.cursor()
    px=cur.execute(query)
    con.commit()
    return px

    

def freopen(filename, mode):
    if mode == "r":
        sys.stdin = open(filename, mode)

    elif mode == "w":
        sys.stdout = open(filename, mode)


# freopen("input.txt", "r") #Uncomment this code to give input from input.txt and see output in output.txt
# freopen("output.txt", "w")


############################################### RSA cryptography for Digital signature ###############################################

def key_gen():
    encryptor = SigningKey.generate()
    decryptor = encryptor.verifying_key
    #print(encryptor.to_string())
    return decryptor, encryptor


def encrypt(pr_key, text):
    pr_key=SigningKey.from_string(bytes.fromhex(pr_key))
    encrypted = pr_key.sign(text.encode())
    return encrypted


def verify(public_key, data, ct):
    public_key=VerifyingKey.from_string(bytes.fromhex(public_key))
    return public_key.verify(ct,data.encode())
   # print(decrypted, data)

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
    def __init__(self, id,public_key,private_key):
        self.id = id
        self.chain = []
        self.transactions = []
        self.mem_pool = []
        self.private_key = private_key
        self.public_key = public_key
        self.wallet=wallet(public_key,private_key)

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


def create_tables():
    cur = con.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users(NAME Varchar(1000),ID VARCHAR(2000),PUBLIC_KEY VARCHAR(2000),PRIVATE_KEY VARCHAR(2000))")
    con.commit()
    cur.execute("CREATE TABLE IF NOT EXISTS miners(ID VARCHAR(1000),PUBLIC_KEY VARCHAR(2000),PRIVATE_KEY VARCHAR(2000))")
    con.commit()
    cur.execute("CREATE TABLE IF NOT EXISTS blocks(ID VARCHAR(100),TIMESTAMP VARCHAR(1000),NONCE VARCHAR(1000),CUR_HASH VARCHAR(1000),PREV_HASH VARCHAR(1000),MERKLE_ROOT VARCHAR(1000),TRANSACTION_HASH VARCHAR(1000))")
    con.commit()
    cur.execute("CREATE TABLE IF NOT EXISTS transactions (TRANSACTION_HASH VARCHAR(1000),FROM_USER VARCHAR(1000),TO_USER VARCHAR(1000),AMOUNT INT,TRANSACTION_FEE INT,ID VARCHAR(1000),SIGNATURE VARCHAR(2000),PUBLIC_KEY VARCHAR(2000))")
    con.commit()
    cur.execute("CREATE TABLE IF NOT EXISTS user_wallet (ID VARCHAR(1000),ADDRESS VARCHAR(2000),UTXO VARCHAR(2000))")
    con.commit()
    cur.execute("CREATE TABLE IF NOT EXISTS miner_wallet (ID VARCHAR(1000),ADDRESS VARCHAR(2000),UTXO VARCHAR(2000))")
    con.commit()
    c = 0
    for i in range(0, 10):
        c += 1
        x, y = key_gen()
        x=x.to_string().hex()
        y=y.to_string().hex()
        miner_new = miner(i,x,y)
        miner_p = copy.copy(miner_new)
        miner_p.mem_pool = []
        idm=str(miner_p.id)
        private_keym=miner_p.private_key
        public_keym=miner_p.public_key
        
        #print((private_keym))
        qry=f"INSERT INTO miners VALUES ('{idm}','{public_keym}','{private_keym}')"
        cur.execute(qry)
        con.commit()
        w=miner_p.wallet
        xx=w.utxo
        #print((xx))
        qry=f'INSERT INTO miner_wallet VALUES ("{miner_p.id}","{w.address}","{xx}")'
        cur.execute(qry)
        con.commit()
        
        
        
        
        
        # print(miner_p.id)

        x, y = key_gen()
        x=x.to_string().hex()
        y=y.to_string().hex()
        
        #print(private_pem)
        #print(x._hashObj,x._label)
        
        
        u1 = user(f"User{c}", c, x, y)
        user1 = copy.copy(u1)
        qry=f"INSERT INTO users VALUES ('{u1.name}','{u1.id}','{u1.public_key}','{u1.private_key}')"
        cur.execute(qry)
        con.commit()
        w=u1.wallet
        xx=w.utxo
        #print((xx))
        #print(u1.id)
        qry=f'INSERT INTO user_wallet VALUES ("{u1.id}","{w.address}","{xx}")'
        cur.execute(qry)
        con.commit()
        c += 1
        x, y = key_gen()
        x=x.to_string().hex()
        y=y.to_string().hex()
    
        u2 = user(f"User{c}", c, x, y)
        user2 = copy.copy(u2)
        qry=f"INSERT INTO users VALUES ('{u2.name}','{u2.id}','{u2.public_key}','{u2.private_key}')"
        cur.execute(qry)
        con.commit()
        w=u2.wallet
        xx=w.utxo
        #print((xx))
        qry=f'INSERT INTO user_wallet VALUES ("{u2.id}","{w.address}","{xx}")'
        cur.execute(qry)
        con.commit()

        # print(user2.private_key,user2.public_key)
        user1.miner_idx = i
        user2.miner_idx = i
def empty_wallets():
    cur = con.cursor()
    qry=f'DELETE FROM user_wallet'
    cur.execute(qry)
    con.commit()
    qry=f'DELETE FROM miner_wallet'
    cur.execute(qry)
    con.commit()

    
    
def sub_main():
    
    blockchain_instance = blockchain()
    
    cur=con.cursor()
    x=cur.execute("Select * from users").fetchall()
    #print(x)
    users=[]
    for i in x:
        user1=user(i[0],i[1],i[2],i[3])
        qry=f"SELECT * FROM user_wallet WHERE ID= '{i[1]}'"
        p=cur.execute(qry).fetchone()
        #print(p)
        user1.wallet.address=p[1]
        temp=p[2]
        y = ast.literal_eval(temp)
        #print(y)
        user1.wallet.utxo=y
        
        
        users.append(user1)
    blockchain_instance.user_list=users
    miners=[]
    x=cur.execute("Select * from miners").fetchall()
    for i in x:
        miner1=miner(i[0],i[1],i[2])
        qry=f"SELECT * FROM miner_wallet WHERE ID= '{i[0]}'"
        p=cur.execute(qry).fetchone()
        #print(p)
        miner1.wallet.address=p[1]
        temp=p[2]
        y = ast.literal_eval(temp)
        #print(y)
        miner1.wallet.utxo=y
        
        miners.append(miner1)
        
    blockchain_instance.miner_list=miners
    n=cur.execute("Select DISTINCT id from blocks").fetchall()
    n=len(n)
    #print(n)
    for i in range(0,n):
        x=cur.execute(f"Select * from blocks where id='{i}'").fetchall()
        transactions_list=[]
        transaction_hash=[]
        for j in x:
            transaction_hash.append(j[6])
            y=cur.execute(f"Select * from transactions where TRANSACTION_HASH='{j[6]}'").fetchone()
            #print(y)
            t = {"from": f"{y[1]}", "to": f"{y[2]}", "amount": f"{y[3]}",
                     "reward": f"{y[4]}", "id": f"{y[5]}"}
            t["digital_signature"] = y[6]
            t["public_key"] = y[7]
            transactions_list.append(t)
        x=x[0]
        block1=block(x[4], x[0], transactions_list)
        block1.cur_hash=x[3]
        block1.timestamp=x[1]
        block1.nonce=x[2]
        block1.merkle_root=x[5]
        block1.transactions=transactions_list
        block1.tarnsactions_hash=transaction_hash
        blockchain_instance.chain.append(block1)
        
            
            
        
    # for i in x:
    #     block1=block(i[4], i[0], transactions)
    #     # print(blockchain_instance.miner_list)
    
    
   # print(blockchain_instance.miner_list)
    while True:
        print("0 => Print Blockchain \n1 => Enter transactions\n2 => Print the wallets of users and miners\n3 => Print Genesis block") 
        print("4 => Find the addresses and amounts of the transactions")
        print("5 => Show the block information of the block with the hash address\n6 => the height of the most recent block stored\n7 => Show the most recent block stored\n8 => average number of transactions per block")
        print("9 => Summary report of the transactions in the block with height\nElse => Exit")
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
                #print(len(user1.public_key))
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
                ind = int(blockchain_instance.chain[-1].index)+1
            
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
                txx=new_block.transactions
                th=new_block.tarnsactions_hash
                for i in range(0,len(txx)):
                    tran=txx[i]
                    thh=th[i]
                    qry=f'INSERT INTO blocks VALUES ("{new_block.index}","{new_block.timestamp}","{new_block.nonce}","{new_block.cur_hash}","{new_block.prev_hash}","{new_block.merkle_root}","{thh}")'
                    cur.execute(qry)
                    con.commit()
                    qry=f'INSERT INTO transactions VALUES ("{thh}","{tran["from"]}","{tran["to"]}","{tran["amount"]}","{tran["reward"]}","{tran["id"]}","{tran["digital_signature"]}","{tran["public_key"]}")'
                    cur.execute(qry)
                    con.commit()
                    
                    
                    

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
        elif a=="3":
            qry=f'SELECT * FROM blocks WHERE id="0"'
            xx=cur.execute(qry).fetchall()
            if(len(xx)==0):
                print("Genesis block not present")
                continue
            thash=[]
            for x in xx:
                thash.append(x[6])
            print("\n")
            print("Block Height:",xx[0][0])
            print("Previous hash", xx[0][4])
            print("Hash of genesis block: ", xx[0][3])
            print("nonce", xx[0][2])
            print("timestamp", xx[0][1])
            print("Merkle root", xx[0][5])
            print("Transactions hash",thash)
            print("\n")
        elif a=="4":
            qry=f"Select * from transactions"
            xx=cur.execute(qry).fetchall()
            for x in xx:
                print("\n")
                print("Transaction Hash",x[0])
                print("From",x[1])
                print("To",x[2])
                print("Amount",x[3])
                print("Transaction fee",x[4])
                print("\n")
        elif a=="5":
            hashv=input("Enter hash of the block: ")
            qry=f"Select * from blocks where cur_hash='{hashv}'"
            xx=cur.execute(qry).fetchall()
            if(len(xx)==0):
                print("Such block not present")
                continue
            thash=[]
            for x in xx:
                thash.append(x[6])
            print("\n")
            print("Block Height:",xx[0][0])
            print("Previous hash", xx[0][4])
            print("Current hash", xx[0][3])
            print("nonce", xx[0][2])
            print("timestamp", xx[0][1])
            print("Merkle root", xx[0][5])
            print("Transactions hash",thash)
            print("\n")
        elif a=="6":
            qry="SELECT MAX(id) from blocks"
            xx=cur.execute(qry).fetchone()
            print("Height of most recent block= ",xx[0])
            
        elif a=="7":
            qry="SELECT * from blocks b where b.id=(SELECT MAX(id) from blocks)"
            xx=cur.execute(qry).fetchall()
            if(len(xx)==0):
                print("Such block not present")
                continue
            thash=[]
            for x in xx:
                thash.append(x[6])
            print("\n")
            print("Block height:",xx[0][0])
            print("Previous hash", xx[0][4])
            print("Current hash", xx[0][3])
            print("nonce", xx[0][2])
            print("timestamp", xx[0][1])
            print("Merkle root", xx[0][5])
            print("Transactions hash",thash)
            print("\n")
        elif a=="8":
            qry="SELECT COUNT(DISTINCT id) FROM blocks"
            x=cur.execute(qry).fetchone()[0]
            qry2="SELECT COUNT(transaction_hash) FROM transactions"
            y=cur.execute(qry2).fetchone()[0]
            print(x)
            print(y)
            print("Average number of transactions per block = ",y/x)
            print('\n')
            
        elif a=="9":
            h=input("Enter Block number")
            qry=f"Select count(transaction_hash) from blocks where id='{h}'"
            xx=cur.execute(qry).fetchone()
            print("No of transactions",xx[0])
            qry=f"Select SUM(a.amount),SUM(a.transaction_fee) from blocks AS b INNER JOIN transactions AS a ON a.transaction_hash=b.transaction_hash WHERE b.id='{h}'"
            xx=cur.execute(qry).fetchone()
           #print(xx)
            
            print("Total bitcoin/currency= ",xx[0]+xx[1])
            
            
            
        else:
            
            empty_wallets()
            users=blockchain_instance.user_list
            miners=blockchain_instance.miner_list
            for x in users:
                w=x.wallet

                xx=w.utxo
                #print((xx))
                qry=f'INSERT INTO user_wallet VALUES ("{x.id}","{w.address}","{xx}")'
                cur.execute(qry)
                con.commit()
            for x in miners:
                w=x.wallet

                xx=w.utxo
                #print((xx))
                qry=f'INSERT INTO miner_wallet VALUES ("{x.id}","{w.address}","{xx}")'
                cur.execute(qry)
                con.commit()
                
            
            break
#create_tables()
sub_main()


##Copyright Knightmare b19cse053