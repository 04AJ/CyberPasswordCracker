import codecs
import hashlib
import datetime as dt
import bcrypt

# secList
secList = open("secList.txt", "r")
list = [((line.encode('utf-8')).strip()).split() for line in secList]

key = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
       'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?', '@', '[', ']', '^', '_', '`', '{', '|', '}', '~']
arr = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
       'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

# arr = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
#        'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']


# MD5 hash


def md5hash(pswd):
    encrypt = hashlib.md5(pswd)
    return encrypt.hexdigest().encode('utf-8')

# BCrypt Hash


def bcry(pswd):
    encrypt = bcrypt.hashpw(pswd, bcrypt.gensalt())
    return encrypt

# SHA-256 Hash


def sha(pswd):
    encrypt = hashlib.sha256(pswd)
    return encrypt.hexdigest().encode('utf-8')

# DictionaryAttackFunction


def dictAttack(secList, actualPassword, type):
    start = dt.datetime.now()
    pswd = actualPassword.encode('utf-8')
    # result = secList[0]
    for word in secList:
        # print(bcry(word[0]).decode())
        if type == "P":
            if word[0] == pswd:
                end = dt.datetime.now()
                result = word[0].decode('utf-8')
                print("Password: {} in {}".format(result, end - start))
                return None
                break
        if type == "M":
            if md5hash(word[0]) == pswd:
                end = dt.datetime.now()
                result = word[0].decode('utf-8')
                print("Password: {} in {}".format(result, end - start))
                return None
                break
        if type == "B":
            if bcrypt.checkpw(word[0], pswd):
                end = dt.datetime.now()
                result = word[0].decode('utf-8')
                print("Password: {} in {}".format(result, end - start))
                return None
                break
        if type == "S":
            if sha(word[0]) == pswd:
                end = dt.datetime.now()
                result = word[0].decode('utf-8')
                print("Password: {} in {}".format(result, end - start))
                return None
                break

    return print("Password Not Found")


# BruteForceAttackFunction
def pbrute(actualPassword):
    start = dt.datetime.now()

    guess = ""
    count = 0
    while(count < len(actualPassword)):
        if count == 0:
            for char in key:
                guess += char
                if(guess[:count] == actualPassword[:count]):
                    break
                else:
                    guess = ""

        count += 1
        while(guess != actualPassword):
            for char in key:
                guess += char
                if(guess[:count] == actualPassword[:count]):
                    count += 1
                    break
                else:
                    guess = guess[:count-1]
    end = dt.datetime.now()
    print("Password: {} in {}".format(guess, end - start))


# md5 brute force via https://www.geeksforgeeks.org/print-all-the-permutation-of-length-l-using-the-elements-of-an-array-iterative/
def printf(arr, Len, L, actual, type):
    start = dt.datetime.now()
    # There can be (Len)^l permutations
    for i in range(pow(Len, L)):

        # Convert i to Len th base
        if type.upper() == "M":
            if mbrute(i, arr, Len, L, actual, start) == True:
                break
        elif type.upper() == "B":
            if bbrute(i, arr, Len, L, actual, start) == True:
                break
        elif type.upper() == "S":
            if sbrute(i, arr, Len, L, actual, start) == True:
                break


def mbrute(n, arr, Len, L, actual, start):

    nWord = ""
    # Sequence is of Length L
    for i in range(L):
        word = arr[n % Len]
        n //= Len
        nWord += word
        if len(nWord) == L:
            if md5hash(nWord.encode()).decode() == actual:
                end = dt.datetime.now()
                print("Password: {} in {}".format(nWord, end - start))
                return True
                break


def sbrute(n, arr, Len, L, actual, start):

    nWord = ""
    # Sequence is of Length L
    for i in range(L):
        word = arr[n % Len]
        n //= Len
        nWord += word
        if len(nWord) == L:
            if sha(nWord.encode()).decode() == actual:
                end = dt.datetime.now()
                print("Password: {} in {}".format(nWord, end - start))
                return True
                break


def bbrute(n, arr, Len, L, actual, start):
    nWord = ""
    pswd = actual.encode('utf-8')
    # Sequence is of Length L
    for i in range(L):
        word = arr[n % Len]
        n //= Len
        nWord += word
        if len(nWord) == L:
            if bcrypt.checkpw(nWord.encode('utf-8'), pswd):
                end = dt.datetime.now()
                print("Password: {} in {}".format(nWord, end - start))
                return True
                break


# User Input
while(True):
    attack = input("Dictionary (D), Brute Force (B) or Create Hash(H)? ")
    if attack.upper() == "D":
        type = input(
            "Enter the type of password: Plain(P), MD5(M), BCrypt(B) or SHA-256(S): ").upper()
        pswd = input("Enter your password: ")
        if type == "P":
            dictAttack(list, pswd, "P")
        if type == "M":
            dictAttack(list, pswd, "M")
        if type == "B":
            dictAttack(list, pswd, "B")
        if type == "S":
            dictAttack(list, pswd, "S")
            # password = password.encode('utf-8')

    elif attack.upper() == "B":
        type = input(
            "Enter the type of password: Plain(P), MD5(M), BCrypt(B) or SHA-256(S) ")
        if type.upper() == "M" or type.upper() == "B" or type.upper() == "S":
            letters = input("How many letters is the plaintext? ")
            password = input("Enter your alphanumeric password: ")
            printf(key, int(len(arr)), int(letters), password, type)
        if type.upper() == "P":
            password = input("Enter your alphanumeric password: ")
            pbrute(password)
    elif attack.upper() == "H":
        password = input("Enter your alphanumeric password: ").encode('utf-8')
        type = input("MD5(M), Bcrypt(B), or Sha256(S)? ").upper()
        if type == "M":
            print(md5hash(password).decode())
        if type == "B":
            print(bcry(password).decode())
        if type == "S":
            print(sha(password).decode())

    else:
        print("Invalid")
