 # **Mayank Raj (B19CSE053)**
 # **Assignment-1**

 ## Readme

 ### Requirements

* Python
* Pycryptodome
 ```py
pip install pycryptodome
 ```

---
### To run

```bash
python B19CSE053_ledger.py
```

---


**Notes** All users have 100 coins initially
 
### Input Format

0 => Print the blochchain

eg:

```py
0 #print blockchain
```

1 => Add transactions

After entering 1:

Transaction input format:

no. of transactions

index_of_user1 index_of_user2 transaction_amount transaction_fee

**Note: Users index are from 1 to 20 and miner index are from 0 to 9**

eg:

```py
1 #Enter Transaction
3#Number of transac
1 2 50 15 #Transactions details user1 user2 amount transaction_fee/reward

```

2 => Print wallets of users and miners

eg:
```py
2 #Print wallets
```

3 => exit


---

**Note** : Uncomment line 24 and 25 to give input from input.txt and see output in output.txt

* Implemented everything mentioned in the problem