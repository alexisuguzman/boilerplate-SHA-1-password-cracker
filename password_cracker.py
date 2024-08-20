import hashlib

def load_passwords(): 
    with open("top-10000-passwords.txt", "r") as file:
        passwords = file.read().splitlines()
    return passwords

def load_salts(): 
    with open("known-salts.txt", "r") as file:
        salts = file.read().splitlines()
    return salts


def crack_sha1_hash(hash, use_salts = False):
    passwords = load_passwords()

    if use_salts == True:
        salts = load_salts()

    for password in passwords:
        password_bytes = password.encode('utf-8')
        if use_salts == True:
            #First prepend all salts
            for salt in salts:
                hasher = hashlib.sha1()
                hasher.update(salt.encode('utf-8') + password_bytes)
                hashed_password = hasher.hexdigest()

                if hashed_password == hash:
                    return password
            #Now append all salts
            for salt in salts:
                hasher = hashlib.sha1()
                hasher.update(password_bytes + salt.encode('utf-8'))
                hashed_password = hasher.hexdigest()

                if hashed_password == hash:
                    return password
        else:
            hasher = hashlib.sha1()
            hasher.update(password_bytes)
            hashed_password = hasher.hexdigest()
            if hashed_password == hash:
                return password
    return("PASSWORD NOT IN DATABASE")
    
result = crack_sha1_hash(
            "ea3f62d498e3b98557f9f9cd0d905028b3b019e1", use_salts=True) 
print(result)
