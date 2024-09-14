 # **Mayank Raj (B19CSE053)**
 # **Blockchain Assignment 2**

## README

i) Install ecdsa

```py
pip install ecdsa
```

ii) Install sqlite3

```py
pip install sqlite3
```

iii) To create new databse
 - Delete tutorial.db if present
 - run database.py

```py
python database.py
```
iv) After creating the database just run ledger.py

```py
python ledger.py
```

After which in terminal we can do all the functionalities mentioned in the problem. You will see something like this:

![](https://github.com/Mayank9mare/ImagesForMarkdown/blob/main/bc1.png?raw=true)

- To print whole blockchain enter 0

- To enter transactions enter 1, then enter number of transactions to be added after which add transaction in this order => **from to amount transactionfee**
- Note: User are number 1 to 20
- For all other functionality that were asked, you just need to enter number mentioned in the terminal. For example if you want the addresses and amounts of the transactions, enter 4.

![](https://github.com/Mayank9mare/ImagesForMarkdown/blob/main/bc2.png?raw=true)

- Similarly all functionality asked in the assignment can be done.

**Note** I have already provided tutorial.db file , if you wish create new database follow above steps of database creation.

**Note** Always exits by 10 or other value. Do not exit using ctrl+C as database may crash.

**Note** Block height starts from 0(Assumption).
