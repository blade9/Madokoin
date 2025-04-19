import datetime
import sys
import hashlib
from hashlib import sha256
from time import strftime
import binascii
import rsa
import re
import os

def print_name():
    print("MadoKoin Magical Crypto")

def genesis():
    genesis_file = open("block_0.txt", "w+")
    genesis_file.write("The Contract has been signed. Genesis block created")
    genesis_file.close()
    mem_file = open("mempool.txt", "w+")
    mem_file.close()
    print("The Contract has been signed. Genesis block created")


# given an array of bytes, return a hex reprenstation of it
def bytesToString(data):
    return binascii.hexlify(data)


def stringToBytes(hexstr):
    return binascii.a2b_hex(hexstr)


def hashFile(filename):
    h = hashlib.sha256()
    with open(filename, 'rb', buffering=0) as f:
        for b in iter(lambda : f.read(128*1024), b''):
            h.update(b)
    return h.hexdigest()


def load_wallet(filename):
    with open(filename, mode='rb') as file:
        keydata = file.read()
    privkey = rsa.PrivateKey.load_pkcs1(keydata)
    pubkey = rsa.PublicKey.load_pkcs1(keydata)
    return pubkey, privkey


def save_wallet(pubkey, privkey, filename):
    # Save the keys to a key format (outputs bytes)
    pubkey_bytes = pubkey.save_pkcs1(format='PEM')
    privkey_bytes = privkey.save_pkcs1(format='PEM')
    # Convert those bytes to strings to write to a file (gibberish, but a string...)
    pubkey_string = pubkey_bytes.decode('ascii')
    privkey_string = privkey_bytes.decode('ascii')
    # Write both keys to the wallet file
    with open(filename, 'w') as file:
        file.write(pubkey_string)
        file.write(privkey_string)
    return


def generate_wallet(filename):
    (pub_key, priv_key) = rsa.newkeys(1024)
    save_wallet(pub_key, priv_key, filename=filename)
    to_encode = pub_key.save_pkcs1().decode('ascii')
    to_encode = re.search('\n(.*)\n', to_encode).group(1)
    tag = sha256(to_encode.encode('utf-8')).hexdigest()
    print("New Soul Stone made for " + filename + " ID is : " + tag[:16])


def get_tag(filename):
    (pub_key, priv_key) = load_wallet(filename)
    to_encode = pub_key.save_pkcs1().decode('ascii')
    to_encode = re.search('\n(.*)\n', to_encode).group(1)
    tag = sha256(to_encode.encode('utf-8')).hexdigest()
    return tag[:16]


def get_address(filename):
    print(get_tag(filename))


def add_signature(sender_name, entry):
    (pub_key, priv_key) = load_wallet(sender_name)
    ret_entry = entry + " Signature: " + bytesToString(rsa.sign(entry.encode(), priv_key, "SHA-256")).decode()
    return ret_entry


def transaction_line_string(send_tag, rec_tag, amount):
    entry = send_tag + " gave " + amount + " grief seeds to " + rec_tag
    entry = entry + " on " + datetime.datetime.now().strftime("%B %d, %Y")
    entry = entry + " at " + datetime.datetime.now().strftime("%I:%M:%S %p ") + "EST"

    return entry


def transaction_statement_string(sender_name, rec_tag, amount):
    entry = transaction_line_string(sender_name, rec_tag, amount)
    ret_entry = add_signature(sender_name, entry)
    return ret_entry


def funds(tag, amount, filename):
    entry = transaction_line_string("kyubey", tag, amount)
    fund_file = open(filename, "w")
    fund_file.write(entry)
    fund_file.close()
    print(entry + " in contract " + filename)


def transfer(source_wallet_name, dest_tag, amount, new_file):
    entry = transaction_line_string(get_tag(source_wallet_name), dest_tag, amount)
    print(entry + " in contract " + new_file)
    entry = add_signature(source_wallet_name, entry)
    trans_file = open(new_file, 'w')
    trans_file.write(entry + "\n")
    trans_file.close()


def parse_statement_line(tag, line):
    list_of_words = line.split(" ")
    if tag in list_of_words:
        titles = {"Sender": list_of_words[0], "Receiver": list_of_words[list_of_words.index("to") + 1],
                  "Amount": int(list_of_words[list_of_words.index("gave") + 1])}
        return titles
    else:
        return


def balance(tag):
    counter = 0
    current_balance = 0

    if os.path.isfile("./mempool.txt"):
        mempool_file = open("mempool.txt", 'r')
        line = mempool_file.readline()
        while line:
            list_of_words = line.split(" ")
            if tag in list_of_words:
                titles = {"Sender": list_of_words[0], "Receiver": list_of_words[list_of_words.index("to") + 1],
                          "Amount": int(list_of_words[list_of_words.index("gave") + 1])}
                if titles["Sender"] == tag:
                    current_balance -= titles["Amount"]
                elif titles["Receiver"] == tag:
                    current_balance += titles["Amount"]
            line = mempool_file.readline().strip()

    while os.path.isfile("./block_"+str(counter) + ".txt"):
        cur_block = open("block_"+str(counter) + ".txt", 'r')
        line = cur_block.readline()
        while line:
            list_of_words = line.split(" ")
            if tag in list_of_words:
                titles = {"Sender": list_of_words[0], "Receiver": list_of_words[list_of_words.index("to") + 1],
                  "Amount": int(list_of_words[list_of_words.index("gave")+1])}
                if titles["Sender"] == tag:
                    current_balance -= titles["Amount"]
                elif titles["Receiver"] == tag:
                    current_balance += titles["Amount"]
            line = cur_block.readline()
        counter += 1
    return current_balance


def verify(wallet_file_name, transaction_statement):
    tag = get_tag(wallet_file_name)
    amountneeded = 0
    signature = 0
    if os.path.isfile(transaction_statement):
        trans_file = open(transaction_statement, 'r')
        line = trans_file.readline()
        while line:
            list_of_words = line.split(" ")
            if tag in list_of_words:
                titles = {"Sender": list_of_words[0],
                          "Amount": int(list_of_words[list_of_words.index("gave") + 1])}
                if titles["Sender"] != "kyubey":
                    titles["Signature"] = list_of_words[list_of_words.index("Signature:") + 1]
                else:
                    trans_file_to_add = open(transaction_statement, 'r')
                    full_text = trans_file_to_add.read()
                    mem_file_to_add = open("mempool.txt", 'a')
                    mem_file_to_add.write(full_text + "\n")
                    mem_file_to_add.close()
                    print("Kyubey forced grief seeds!!!")
                    return
                if titles["Sender"] == tag:
                    amountneeded += titles["Amount"]
                    signature = titles["Signature"]
            line = trans_file.readline()
        trans_file.close()
    try:
        trans_file = open(transaction_statement, 'r')
        full_text = trans_file.read()
        full_text = full_text[:full_text.index(" Signature:")]
        (pub_key, priv_key) = load_wallet(wallet_file_name)
        rsa.verify(full_text.encode(), stringToBytes(signature.strip()), pub_key)
        if balance(tag) >= amountneeded:
            print("Successfully verified.  Now adding to mempool")
            mem_file = open("mempool.txt", 'a')
            list_of_word = full_text.split(" ")
            titles = {"Sender": list_of_words[0], "Receiver": list_of_words[list_of_words.index("to") + 1],
                      "Amount": int(list_of_words[list_of_words.index("gave") + 1])}
            mem_file.write(full_text + "\n")
            mem_file.close()
        else:
            print("Not enough funds in balance")
            print("You have " + str(balance(tag)) + " madokoins")
    except rsa.VerificationError:
        print("Error, could not verify signature")


def mine(difficulty):
    block_to_make = 0
    while os.path.isfile("./block_"+str(block_to_make) + ".txt"):
        block_to_make+=1

    if block_to_make >= 1:
        last_block = open("block_"+str(block_to_make-1)+".txt", "r")
        mem_block = open("mempool.txt", "r+")
        keydata = last_block.read()
        mem_data = mem_block.read()
        mem_block.close()
        open('mempool.txt', 'w').close()

        last_hash = sha256(keydata.encode('utf-8')).hexdigest()
        num_zeros = 0
        nonce = 0

        new_block = open("block_" + str(block_to_make) + ".txt", "w")
        entry = last_hash + "\n" + mem_data + "\n" + "nonce: " + str(nonce)
        new_block.write(entry)
        new_block.close()

        while difficulty != num_zeros:
            new_block = open("block_" + str(block_to_make) + ".txt", "w")
            entry = last_hash + "\n" + mem_data + "\n" + "nonce: " + str(nonce)
            new_block.write(entry)
            my_hash = sha256(entry.encode('utf-8')).hexdigest()
            num_zeros = str(my_hash[:int(difficulty)].count("0"))
            nonce += 1
            new_block.close()


def validate():
    block_to_check = 1
    while os.path.isfile("./block_"+str(block_to_check) + ".txt"):
        cur_block = open("block_"+str(block_to_check) + ".txt", "r")
        last_block = open("block_"+str(block_to_check-1) + ".txt", "r")
        cur_hash_last_hash = cur_block.readline().strip("\n")
        last_hash = hashFile("block_"+str(block_to_check-1) + ".txt")
        if cur_hash_last_hash != last_hash:
            print("False")
            return "False"
        block_to_check+=1
    print("True")
    return "True"


try:
    if sys.argv[1] == 'name':
        print_name()
    elif sys.argv[1] == 'genesis':
        genesis()
    elif sys.argv[1] == 'generate':
        generate_wallet(sys.argv[2])
    elif sys.argv[1] == 'address':
        get_address(sys.argv[2])
    elif sys.argv[1] == 'fund':
        funds(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == 'transfer':
        transfer(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    elif sys.argv[1] == 'balance':
        print(balance(sys.argv[2]))
    elif sys.argv[1] == 'verify':
        verify(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == 'mine':
        mine(sys.argv[2])
    elif sys.argv[1] == 'validate':
        validate()
    else:
        print("But nothing happened")
except IndexError:
    print("Not enough inputs")

