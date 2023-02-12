from Crypto.Cipher import AES
import random

def convertHexToBase64(input_hex):  # 输入hex样式的字符串，输出base64
    Base64_space = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    # Check if the input is string or hex
    try:
        input_str = bytes.fromhex(input_hex).decode()
    except:
        input_str = input_hex

    # Group characters into groups of three, check for redundant characters
    remainder = len(input_str) % 3
    # Group number
    group_number = len(input_str) // 3


    tmp_list = []
    base64_str = ""

    # Group the string
    for i in range(group_number+1):
        try:
            if input_str[i*3:i*3+3] != "":
                tmp_list.append(input_str[i*3:i*3+3])
        except:
            tmp_list.append(input_str[i*3:i*3+remainder])
    

    for i in range(len(tmp_list)):
        tmp_bin = ""
        remaining_char = ""
        for j in range(len(tmp_list[i])):
            tmp_bin_char = bin(ord(tmp_list[i][j]))[2:]     # Char -> ASCII -> binary
            tmp_len = 8 - len(tmp_bin_char)     # Add 0 in front of the binary
            
            # each group is three characters
            if len(tmp_list[i]) == 3:
                for k in range(tmp_len):
                    tmp_bin_char = "0" + tmp_bin_char
                tmp_bin += tmp_bin_char  # 3 chars -> 24 bits binary

            # when the group lacks one char
            elif len(tmp_list[i]) == 2:
                for k in range(tmp_len):
                    tmp_bin_char = "0" + tmp_bin_char
                tmp_bin_char = remaining_char + tmp_bin_char
                tmp_bin_char = ("00" + tmp_bin_char)    # add 0 in the front of the char binary
                remaining_char = tmp_bin_char[8:]
                tmp_bin_char = tmp_bin_char[:8]
                tmp_bin += tmp_bin_char
                if j == 1:
                    tmp_bin += "00"+remaining_char + "00"
                # for example "MA" -> 01001101, 01100001 -> 00010011, 00010110,0000100 -> TWE
                # then add "=" at the end of TWE
            
            else:
                for k in range(tmp_len):
                    tmp_bin_char = "0" + tmp_bin_char
                tmp_bin_char = remaining_char + tmp_bin_char
                tmp_bin_char = ("00" + tmp_bin_char)
                remaining_char = tmp_bin_char[8:]
                tmp_bin_char = tmp_bin_char[:8]
                tmp_bin += tmp_bin_char
                tmp_bin += "00"+remaining_char + "0000"
                # for example "M" -> 01001101 -> 00010011,00010000 -> TQ
                # then add two "=" at the end

                
        if len(tmp_list[i]) == 3:
            for j in range(4):
                base64_str += Base64_space[int(tmp_bin[j*6:j*6+6], 2)]  # 24 bits binary -> 4 parts -> 4 Chars
        elif len(tmp_list[i]) == 2:
            for j in range(3):
                base64_str += Base64_space[int(tmp_bin[j*8:j*8+8], 2)]
            base64_str += "="   # add "=" at the end
        else:
            for j in range(2):
                base64_str += Base64_space[int(tmp_bin[j*8:j*8+8], 2)]
            base64_str += "=="  # add two "=" at the end

    return base64_str

def hex_XOR(hex1, hex2):    # 输入两个hex样式的字符串，输出他们的XOR结果
    hex1_int = int(hex1, 16)
    hex1_int = int(hex2, 16)
    return hex(hex1_int ^ hex1_int)[2:]

def bytes_XOR(byte1, byte2):
    result = b""
    for i in range(len(byte1)):
        result += bytes([byte1[i] ^ byte2[i]])
    return result

def scoring(text):  # 输入一个text，进行评分
    score = 0
    # a - z: 97 - 112
    # A - Z: 65 - 90
    # 0 - 9: 49 - 57
    # space: 32
    for char in text:
        if ord(char) == 32:
            score += 5
        if 97 <= ord(char)<= 112 or 65 <= ord(char) <= 90 :
            score += 3
        if 49 <= ord(char) <= 57:
            score += 1
    return score

def singlechar_XOR_Decrypt(input_hex):  # 输入hex样式的字符串，循环不同的char对其解密，明文进行评分，输出分最高的明文和加密用的char
    hex_list = []
    char_list = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 :;\'\"#$%^&*~`"
    bin_str = ""
    score = 0
    max_score = 0
    max_score_char = ""
    max_score_str = ""

    # Group the inputs by two and convert them to binary representation. 
    while len(input_hex) != 0:
        hex_list.append(input_hex[:2])
        input_hex = input_hex[2:]
    # Complete the binary bits into eight bits.
    for i in range(len(hex_list)):
        tmp_bin = bin(int(hex_list[i], 16))[2:]
        for j in range(8 - len(tmp_bin)):
            tmp_bin = "0" + tmp_bin
        bin_str += tmp_bin


    for char in char_list:
        bin_char = ""
        XOR_bin = ""
        XOR_str = ""
        tmp_bin_char = bin(ord(char))[2:]
        
        # Converts characters to binary
        # Adds the length to the "input" length.
        for i in range(8 - len(tmp_bin_char)):
            tmp_bin_char = "0" + tmp_bin_char
        for i in range(len(bin_str) // 8):
            bin_char += tmp_bin_char
        
        # Perform XOR operations
        for i in range(len(bin_str)):
            if bin_str[i] == bin_char[i]:
                XOR_bin += "0"
            else:
                XOR_bin += "1"

        # Converts the result after XOR into characters.
        while len(XOR_bin) != 0:
            XOR_str += chr(int(XOR_bin[:8],2))
            XOR_bin = XOR_bin[8:]
        
        # Perform scoring
        score = scoring(XOR_str)
        if score > max_score:
            max_score_char = char
            max_score_str = XOR_str
            max_score = score
    return max_score_str,max_score_char

def repeatedKeyXOREncrypt(plaintext, key): # 将key重复至text的长度，然后对text进行XOR加密，最后输出hex样式的字符串
    key_remainder = len(plaintext) % len(key)
    key_padding = ""
    plaintext_bin = ""
    key_bin = ""
    XOR_bin = ""
    ciphertext = ""
    
    # Expand key to text length
    for i in range(len(plaintext) // len(key)):
        key_padding += key
    key_padding += key[:key_remainder]
    
    # Converting text to binary
    for i in range(len(plaintext)):
        tmp_bin = bin(ord(plaintext[i]))[2:]
        for j in range(8 - len(tmp_bin)):
            tmp_bin = "0" + tmp_bin
        plaintext_bin += tmp_bin

    # Converting key to binary
    for i in range(len(key_padding)):
        tmp_bin = bin(ord(key_padding[i]))[2:]
        for j in range(8 - len(tmp_bin)):
            tmp_bin = "0" + tmp_bin
        key_bin += tmp_bin
    
    # XOR binary text and binary key
    for i in range(len(plaintext_bin)):
        if plaintext_bin[i] == key_bin[i]:
            XOR_bin += "0"
        else:
            XOR_bin += "1"

    # Convert the result of XOR to hex
    while len(XOR_bin) != 0:
        tmp_hex = hex(int(XOR_bin[:8],2))[2:]
        if len(tmp_hex) == 1:
            tmp_hex = "0" + tmp_hex
        ciphertext += tmp_hex
        XOR_bin = XOR_bin[8:]
    return ciphertext

def calculateHammingDistance(string_1, string_2):   # 计算两个字符串之间的汉明距离
    string_1_bin = ""
    string_2_bin = ""
    XOR_bin = ""
    for i in range(len(string_1)):
        tmp_bin = bin(ord(string_1[i]))[2:]
        for j in range(8 - len(tmp_bin)):
            tmp_bin = "0" + tmp_bin
        string_1_bin += tmp_bin
    
    for i in range(len(string_2)):
        tmp_bin = bin(ord(string_2[i]))[2:]
        for j in range(8 - len(tmp_bin)):
            tmp_bin = "0" + tmp_bin
        string_2_bin += tmp_bin

    for i in range(len(string_1_bin)):
        if string_1_bin[i] == string_2_bin[i]:
            XOR_bin += "0"
        else:
            XOR_bin += "1"
    
    return XOR_bin.count("1")

def decryptAESECB(ciphertext, key): # 这里要用到 Crypto.Cipher 中的 AES
    AES_ECB_object = AES.new(key, AES.MODE_ECB)
    plaintext = AES_ECB_object.decrypt(ciphertext).decode()
    return plaintext

def addPKCS7Padding(msg, blcok_size):
    # check if we do not need to pad
    if len(msg) == blcok_size:
        return msg

    # If the message length is greater than 
    # the block length, we also need to consider 
    # padding and patching to multiple block lengths.
    
    # start padding
    padding_Block = blcok_size - len(msg) % blcok_size
    return bytes(msg) + bytes((chr(padding_Block) * padding_Block).encode())

def removePKCS7Padding(msg):
    msg_length = len(msg)
    counter = 1
    last_char = msg[-1]
    # Count how many repeating characters 
    # are at the end of the string, 
    # and guess the repeating characters are padding.
    for i in range(2,msg_length):
        if msg[-i] == last_char:
            counter += 1
        else:
            break
    new_msg = msg[:-counter]

    # verify
    repadd_msg = addPKCS7Padding(new_msg, msg_length)

    if repadd_msg == msg:
        return new_msg
    else:
        return msg

def aesECBDecrypt(ciphertext, key):
    AES_ECB_object = AES.new(key, AES.MODE_ECB)
    plaintext = AES_ECB_object.decrypt(ciphertext)
    return plaintext

def aesECBEncrypt(plaintext, key):
    AES_ECB_object = AES.new(key, AES.MODE_ECB)
    ciphertext = AES_ECB_object.encrypt(plaintext)
    return ciphertext

def aesCBCDecrypt(ciphertext, key, iv): # 输入输出都是 b""格式
    plaintext = b""
    previous_block = iv
    for i in range(0, len(ciphertext), 16):
        current_block = ciphertext[i:i+16]
        current_block_new = aesECBDecrypt(current_block, key)
        current_block_new = bytes_XOR(current_block_new, previous_block)
        plaintext += current_block_new
        previous_block = current_block
    return removePKCS7Padding(plaintext)

def aesCBCEncrypt(plaintext, key, iv):  # 输入输出都是 b""格式
    ciphertext = b""
    plaintext = addPKCS7Padding(plaintext, 16)
    previous_block = iv
    for i in range(0, len(plaintext), 16):
        current_block = plaintext[i:i+16]
        current_block_new = bytes_XOR(current_block, previous_block)
        encrypted_block = aesECBEncrypt(current_block_new, key)
        ciphertext += encrypted_block
        previous_block = encrypted_block
    
    return ciphertext

def detectRepeatedBlocks(text):
    most_block_count = 0
    block_dic = {}
    for i in range(0,len(text), 16):
        if text[i:i+16] in block_dic.keys():
            block_dic[text[i:i+16]] += 1
        else:
            block_dic[text[i:i+16]] = 0
    if sum(block_dic.values()) > most_block_count:
        most_block_count = sum(block_dic.values())
    return most_block_count

def generateRandomBytes(BytesLength):
    result = b""
    alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()'
    characters = random.sample(alphabet, BytesLength)
    for char in characters:
        result += bytes(char.encode())
    return result

def encryption_oracle(input_plaintext):
    # generate key and iv
    key = generateRandomBytes(16)
    iv = generateRandomBytes(16)

    # generate padding
    before_padding = generateRandomBytes(random.randint(5, 10))
    after_padding = generateRandomBytes(random.randint(5, 10))
    input_plaintext = before_padding + input_plaintext + after_padding

    # addPKCS7Padding
    input_plaintext = addPKCS7Padding(input_plaintext, 16)

    # choose encrypt mode
    encryption_mode = random.randint(0, 1)
    if encryption_mode == 0:
        return aesECBEncrypt(input_plaintext, key), "ECB"
    else:
        return aesCBCEncrypt(input_plaintext, key, iv), "CBC"

