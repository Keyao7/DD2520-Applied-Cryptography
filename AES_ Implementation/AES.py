import numpy as np
import sys
global key_array
global s_box
global R_con

def readKey(key_hex):
    global key_array
    key_array = np.zeros(shape=(4,4)).astype(np.str_)

    for j in range(4):
        for i in range(4):
            key_array[i][j] = "0x" + key_hex[:2]
            key_hex = key_hex[2:]

def readPlaintext(input_hex,block_count):
    plaintext_array = np.zeros(shape=(4,4 * block_count)).astype(np.str_)
    for j in range(4 * block_count):
        for i in range(4):
            plaintext_array[i][j] = "0x" + input_hex[:2]
            input_hex = input_hex[2:]
            
    return plaintext_array


def setSBox():
    global s_box
    Sbox = [
                [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
                [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
                [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
                [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
                [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
                [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
                [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
                [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
                [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
                [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
                [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
                [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
                [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
                [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
                [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
                [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
                ]
    s_box = np.zeros(shape=(16,16)).astype(np.str_)
    for i in range(16):
        for j in range(16):
            s_box[i][j] = hex(Sbox[i][j])

def setRcon():
    global R_con
    Rcon = [
                [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36],
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
                ]
    R_con = np.zeros(shape=(4,10)).astype(np.str_)
    for i in range(4):
        for j in range(10):
            R_con[i][j] = hex(Rcon[i][j])

def generateNewKeyT(array, round_count):
    letter_trans = "abcdef"
    tmp_array = np.zeros(shape=(4,1)).astype(np.str_)
    # 字循环
    for i in range(4):
        tmp_array[i] = array[(i+1)%4][3]
    # 字节代换
    for k in range(4):
        if len(tmp_array[k][0][2:]) == 2:
            tmp_i = tmp_array[k][0][2:][0]
            tmp_j = tmp_array[k][0][2:][1]
        else:
            tmp_i = "0"
            tmp_j = tmp_array[k][0][2:][0]
        try:
            tmp_i = int(tmp_i)
        except:
            tmp_i = letter_trans.index(tmp_i)+10
        try:
            tmp_j = int(tmp_j)
        except:
            tmp_j = letter_trans.index(tmp_j)+10
        tmp_array[k] = s_box[tmp_i][tmp_j]  
    #轮常量异或
    for l in range(4):
        tmp_array[l] = hex(int(R_con[l][round_count-1], 16) ^ int(tmp_array[l][0], 16) ^ int(array[l][0], 16))
        array[l][4] = tmp_array[l][0]
    return array

def generateNewKey(key_array, round_count):
    tmp_key_array = np.zeros(shape=(4,8)).astype(np.str_)
    new_key_array = np.zeros(shape=(4,4)).astype(np.str_)
    for i in range(4):
        for j in range(4):
            tmp_key_array[i][j] = key_array[i][j]
    for j in range(4,8):
        if j == 4:
            tmp_key_array = generateNewKeyT(tmp_key_array, round_count)
            for i in range(4):
                new_key_array[i][j-4] = tmp_key_array[i][j]
        else:
            for i in range(4):
                tmp_key_array[i][j] = hex(int(tmp_key_array[i][j-4], 16) ^ int(tmp_key_array[i][j-1], 16))
                new_key_array[i][j-4] = tmp_key_array[i][j]
    return new_key_array

def initialRound(array):
    for j in range(4):
        for i in range(4):
            array[i][j] = hex(int(array[i][j], 16) ^ int(key_array[i][j], 16))
    return array

# Directly replace the elements of the matrix according to the S-Box
def subBytes(array):
    letter_trans = "abcdef" # We need to search 10-15 row and column 
    for i in range(len(array)):
        for j in range(len(array)):
            if len(array[i][j][2:]) == 2:
                tmp_i = array[i][j][2:][0]
                tmp_j = array[i][j][2:][1]
            else:
                tmp_i = "0"
                tmp_j = array[i][j][2:][0]
            try:
                tmp_i = int(tmp_i)
            except:
                tmp_i = letter_trans.index(tmp_i)+10
            try:
                tmp_j = int(tmp_j)
            except:
                tmp_j = letter_trans.index(tmp_j)+10
            array[i][j] = s_box[tmp_i][tmp_j]
    return array

# Shift the elements of the matrix to the left by the number of rows
def shiftRows(array):
    result_array = np.zeros(shape=(4,4)).astype(np.str_)
    for i in range(len(array)):
        for j in range(len(array)):
            if i == 0:
                result_array[i][j] = array[i][j]
            elif i == 1:
                result_array[i][j] = array[i][(j + 1)%4]
            elif i == 2:
                result_array[i][j] = array[i][(j + 2)%4]
            else:
                result_array[i][j] = array[i][(j + 3)%4]
    return result_array

#列混合 (MixColumns)
def xtime(char, number):
    char_int = int(char,16)
    if number == 1:
        return char_int
    tmp = (char_int << 1) & 0xff #
    if number == 2:
        return tmp if char_int < 128 else tmp ^ 0x1b
    if number == 3:
        return xtime(char, 2) ^ char_int
        
def mixcolumns_culculate(p1, p2, p3, p4, n):
    if n == 0:
        return hex(xtime(p1, 2) ^ xtime(p2, 3) ^ xtime(p3, 1) ^ xtime(p4, 1))
    elif n == 1:
        return hex(xtime(p1, 1) ^ xtime(p2, 2) ^ xtime(p3, 3) ^ xtime(p4, 1))
    elif n == 2:
        return hex(xtime(p1, 1) ^ xtime(p2, 1) ^ xtime(p3, 2) ^ xtime(p4, 3))
    else:
        return hex(xtime(p1, 3) ^ xtime(p2, 1) ^ xtime(p3, 1) ^ xtime(p4, 2))

def mixcolumns(array):
    result_array = np.zeros(shape=(4,4)).astype(np.str_)
    for i in range(4):
        for j in range(4):
            result_array[j][i] = mixcolumns_culculate(array[0][i], array[1][i], array[2][i], array[3][i], j)
    return result_array

def addRoundKey(array, round_number):
    global key_array
    key_array = generateNewKey(key_array, round_number)
    for j in range(4):
        for i in range(4):
            array[i][j] = hex(int(array[i][j], 16) ^ int(key_array[i][j], 16))
    return array

def main(input_hex):
    input_hex = input_hex.lower()
    key_str = input_hex[:32]
    plaintext_str = input_hex[32:]
    plaintext_block_count = len(plaintext_str) // 2 // 16

    result_array = np.zeros(shape=(4,4)).astype(np.str_)
    # file_path = "test.txt"
    plaintext_array_total = np.zeros(shape=(4,4 * plaintext_block_count)).astype(np.str_)
    result_array_total = np.zeros(shape=(4,4 * plaintext_block_count)).astype(np.str_)
    plaintext_array = np.zeros(shape=(4,4)).astype(np.str_)
    
    plaintext_array_total = readPlaintext(plaintext_str,plaintext_block_count)
    encrypted_str = ""
    setSBox()
    setRcon()

    for index in range(plaintext_block_count):
        readKey(key_str)
        for column1 in range(4):
            for row1 in range(4):
                plaintext_array[row1][column1] = plaintext_array_total[row1][column1 + 4 * index]
    
        # initial round
        plaintext_array = initialRound(plaintext_array)

        # 9 rounds
        for i in range(1,10):
            plaintext_array = subBytes(plaintext_array)
            plaintext_array = shiftRows(plaintext_array)
            plaintext_array = mixcolumns(plaintext_array)
            plaintext_array = addRoundKey(plaintext_array, i)
    
        # final round
        plaintext_array = subBytes(plaintext_array)
        plaintext_array = shiftRows(plaintext_array)
        plaintext_array = addRoundKey(plaintext_array, 10)

        # final result
        result_array = plaintext_array
        # print(result_array)
        # Integrate all result arrays
        for column2 in range(4):
            for row2 in range(4):
                result_array_total[row2][column2 + 4 * index] = result_array[row2][column2]
    
    # Convert the encryption result to a string
    for j in range(4 * plaintext_block_count):
        for i in range(4):
            tmp_result = result_array_total[i][j][2:]
            if len(tmp_result) == 1:
                tmp_result = "0" + tmp_result
            encrypted_str += tmp_result
    print(encrypted_str.upper())
    return encrypted_str.upper()


if __name__ == "__main__":
    main(sys.argv[1])
