import random

def generate_key_64():
    character_set = "0123456789ABCDEFabcdef"
    key_list = []
    for i in range(0, 64):
        key_list.append(character_set[random.randint(0, len(character_set)) - 1])
    return "".join(key_list)

def encrypt(message, key):
    encrypted_list = []
    for i in range(0, len(message)):
        encrypted_list.append(chr(ord(message[i]) + ord(key[i])))
    return "".join(encrypted_list)

def decrypt(message, key):
    decrypted_list = []
    for i in range(0, len(message)):
        try:
            decrypted_list.append(chr(ord(message[i]) - ord(key[i])))
        except ValueError:
            return "BADMSG"
    return "".join(decrypted_list)

def verify_key(key):
    character_set = "0123456789ABCDEFabcdef"
    if not len(key) == 64:
        return False
    for char in key:
        if char not in character_set:
            return False
    return True

if __name__ == "__main__":
    test_key = generate_key_64()
    assert(len(test_key) == 64)
    assert(decrypt(encrypt("ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvxyz0123456789", test_key), test_key) == "ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvxyz0123456789")
    assert(verify_key(test_key))
    assert(not verify_key("this is not a valid key"))
    print("Tests passed.")
