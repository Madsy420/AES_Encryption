#!/usr/bin/env python
# coding: utf-8

# In[1]:


import binascii,sys
import os,msvcrt


# In[ ]:





# In[2]:


#AES Algorithm: 128bit text to 128bit cypher text
#Number of rounds: 10
#Round 1-9: Substitute Bytes ---> Shift Bytes ---> Mix Columns ---> Add Round Key (1 4 word key each)
#Round 10: Substitute Bytes ---> Shift Bytes ---> Add Round Key (1 4 word key)
#1 pre-round: Add Round Key (1 4 word key)

#######################################################

#data - address of the file to be encrypted if addr true, else the data
#cipher_key - a 128 bit key (16 bytes)

#128 bit text is stored and processed in: 4x4 table, each cell is one byte
#128 bit key is stored and processed in: 4x4 table, each cell is one byte

#Substitute bytes:
# We basically have alook up table: 16x16
# We use first 4 bytes as row number and next 4 bytes as column number.
# we look at the resulting value in the lookup table and substitute it in place of the word.
def sub_bytes(byte_matrix,table):
    result_matrix = []
    for byte_row in byte_matrix:
        temp_row = []
        for byte in byte_row:
            row = int(byte[0:6],2)
            col = int('0b' + byte[6:],2)
            temp_row.append('0b' + bin(table[row][col][0])[2:].zfill(8))
            #table is a list of list of binary string (i.e b'ssf' format)
        result_matrix.append(temp_row)
    return result_matrix 
#Shift Word:
#Shift the byte in each row the row's index number of times to the left.
def shift_word(byte_matrix):
    result_matrix = []
    for i in range(4):
        row = byte_matrix[i]
        result_matrix.append(row[i:] + row[:i])
    return result_matrix

#Mix Columns:
#We have a predetermined 4x4 Matrix, we take each of the column multiply it with the Matrix and substitute
#it in the column's place.
E_table = ['01','03','05','0F','11','33','55','FF','1A','2E','72','96','A1','F8','13','35','5F','E1','38','48','D8','73','95','A4','F7','02','06','0A','1E','22','66','AA','E5','34','5C','E4','37','59','EB','26','6A','BE','D9','70','90','AB','E6','31','53','F5','04','0C','14','3C','44','CC','4F','D1','68','B8','D3','6E','B2','CD','4C','D4','67','A9','E0','3B','4D','D7','62','A6','F1','08','18','28','78','88','83','9E','B9','D0','6B','BD','DC','7F','81','98','B3','CE','49','DB','76','9A','B5','C4','57','F9','10','30','50','F0','0B','1D','27','69','BB','D6','61','A3','FE','19','2B','7D','87','92','AD','EC','2F','71','93','AE','E9','20','60','A0','FB','16','3A','4E','D2','6D','B7','C2','5D','E7','32','56','FA','15','3F','41','C3','5E','E2','3D','47','C9','40','C0','5B','ED','2C','74','9C','BF','DA','75','9F','BA','D5','64','AC','EF','2A','7E','82','9D','BC','DF','7A','8E','89','80','9B','B6','C1','58','E8','23','65','AF','EA','25','6F','B1','C8','43','C5','54','FC','1F','21','63','A5','F4','07','09','1B','2D','77','99','B0','CB','46','CA','45','CF','4A','DE','79','8B','86','91','A8','E3','3E','42','C6','51','F3','0E','12','36','5A','EE','29','7B','8D','8C','8F','8A','85','94','A7','F2','0D','17','39','4B','DD','7C','84','97','A2','FD','1C','24','6C','B4','C7','52','F6','01']
print(E_table.__len__())
L_table = ['**','00','19','01','32','02','1A','C6','4B','C7','1B','68','33','EE','DF','03','64','04','E0','0E','34','8D','81','EF','4C','71','08','C8','F8','69','1C','C1','7D','C2','1D','B5','F9','B9','27','6A','4D','E4','A6','72','9A','C9','09','78','65','2F','8A','05','21','0F','E1','24','12','F0','82','45','35','93','DA','8E','96','8F','DB','BD','36','D0','CE','94','13','5C','D2','F1','40','46','83','38','66','DD','FD','30','BF','06','8B','62','B3','25','E2','98','22','88','91','10','7E','6E','48','C3','A3','B6','1E','42','3A','6B','28','54','FA','85','3D','BA','2B','79','0A','15','9B','9F','5E','CA','4E','D4','AC','E5','F3','73','A7','57','AF','58','A8','50','F4','EA','D6','74','4F','AE','E9','D5','E7','E6','AD','E8','2C','D7','75','7A','EB','16','0B','F5','59','CB','5F','B0','9C','A9','51','A0','7F','0C','F6','6F','17','C4','49','EC','D8','43','1F','2D','A4','76','7B','B7','CC','BB','3E','5A','FB','60','B1','86','3B','52','A1','6C','AA','55','29','9D','97','B2','87','90','61','BE','DC','FC','BC','95','CF','CD','37','3F','5B','D1','53','39','84','3C','41','A2','6D','47','14','2A','9E','5D','56','F2','D3','AB','44','11','92','D9','23','20','2E','89','B4','7C','B8','26','77','99','E3','A5','67','4A','ED','DE','C5','31','FE','18','0D','63','8C','80','C0','F7','70','07']
print(L_table.__len__())

def custom_dot(byte_1,byte_2):
    #Algorithm for byte wise dot product in Galois Field:
    #1)Lookup L(byte_1) and L(byte_2)
    #2)Add the two lookup table values we got above
    #3)if the result is greater than FF, then subtract FF from the result
    #4)The E_table(Result) is the dot product required--- Result -  we got above
    int_byte_1 = int(byte_1,2)
    int_byte_2 = int(byte_2,2)
    if int_byte_1 == 1:
        return byte_2
    elif int_byte_2 == 1:
        return byte_1
    elif (int_byte_1 == 0) or (int_byte_2 == 0):
        return '0b00000000'
    else:
        L_byte_1 = L_table[int_byte_1] #hex form
        L_byte_2 = L_table[int_byte_2] #hex form
        sum_byte = int(L_byte_1,16) + int(L_byte_2,16)
        if sum_byte > 255:
            sum_byte -= 255
        return '0b'+bin(int(E_table[sum_byte],16))[2:].zfill(8)

def mix_col(byte_matrix):

    result_matrix = []
    for i in range(4):
        result_matrix.append([bin(int(custom_dot(matrix[i][0],byte_matrix[0][0]),2) ^ int(custom_dot(matrix[i][1],byte_matrix[1][0]),2) ^ int(custom_dot(matrix[i][2],byte_matrix[2][0]),2) ^ int(custom_dot(matrix[i][3],byte_matrix[3][0]),2)), bin(int(custom_dot(matrix[i][0],byte_matrix[0][1]),2) ^ int(custom_dot(matrix[i][1],byte_matrix[1][1]),2) ^ int(custom_dot(matrix[i][2],byte_matrix[2][1]),2) ^ int(custom_dot(matrix[i][3],byte_matrix[3][1]),2)), bin(int(custom_dot(matrix[i][0],byte_matrix[0][2]),2) ^ int(custom_dot(matrix[i][1],byte_matrix[1][2]),2) ^ int(custom_dot(matrix[i][2],byte_matrix[2][2]),2) ^ int(custom_dot(matrix[i][3],byte_matrix[3][2]),2)), bin(int(custom_dot(matrix[i][0],byte_matrix[0][3]),2) ^ int(custom_dot(matrix[i][1],byte_matrix[1][3]),2) ^ int(custom_dot(matrix[i][2],byte_matrix[2][3]),2) ^ int(custom_dot(matrix[i][3],byte_matrix[3][3]),2))])
    for i in range(4):
        for j in range(4):
            element = result_matrix[i][j]
            result_matrix[i][j] = '0b'+element[2:].zfill(8)
    return result_matrix

#Add round key:
#We take n'th word of key xor with n'th word of the state array.
def round_key(byte_matrix,key):
    result_matrix = []
    key = key[2:]
    sub_key = ['0b'+key[i*8:(i+1)*8] for i in range(16)]
    #sub_key_num = [int(m,2) for m in sub_key]
    
    for i in range(4):
        sub_key_index = i
        row = byte_matrix[i]
        result_row = []
        for byte in row:
            result_row.append('0b'+bin(int(byte,2) ^ int(sub_key[sub_key_index],2))[2:].zfill(8))
            sub_key_index += 4
        result_matrix.append(result_row)
    return result_matrix

S_table = ["52","09","6a","d5","30","36","a5","38","bf","40","a3","9e","81","f3","d7","fb","7c","e3","39","82","9b","2f","ff","87","34","8e","43","44","c4","de","e9","cb","54","7b","94","32","a6","c2","23","3d","ee","4c","95","0b","42","fa","c3","4e","08","2e","a1","66","28","d9","24","b2","76","5b","a2","49","6d","8b","d1","25","72","f8","f6","64","86","68","98","16","d4","a4","5c","cc","5d","65","b6","92","6c","70","48","50","fd","ed","b9","da","5e","15","46","57","a7","8d","9d","84","90","d8","ab","00","8c","bc","d3","0a","f7","e4","58","05","b8","b3","45","06","d0","2c","1e","8f","ca","3f","0f","02","c1","af","bd","03","01","13","8a","6b","3a","91","11","41","4f","67","dc","ea","97","f2","cf","ce","f0","b4","e6","73","96","ac","74","22","e7","ad","35","85","e2","f9","37","e8","1c","75","df","6e","47","f1","1a","71","1d","29","c5","89","6f","b7","62","0e","aa","18","be","1b","fc","56","3e","4b","c6","d2","79","20","9a","db","c0","fe","78","cd","5a","f4","1f","dd","a8","33","88","07","c7","31","b1","12","10","59","27","80","ec","5f","60","51","7f","a9","19","b5","4a","0d","2d","e5","7a","9f","93","c9","9c","ef","a0","e0","3b","4d","ae","2a","f5","b0","c8","eb","bb","3c","83","53","99","61","17","2b","04","7e","ba","77","d6","26","e1","69","14","63","55","21","0c","7d"]
E_table = ['01','03','05','0F','11','33','55','FF','1A','2E','72','96','A1','F8','13','35','5F','E1','38','48','D8','73','95','A4','F7','02','06','0A','1E','22','66','AA','E5','34','5C','E4','37','59','EB','26','6A','BE','D9','70','90','AB','E6','31','53','F5','04','0C','14','3C','44','CC','4F','D1','68','B8','D3','6E','B2','CD','4C','D4','67','A9','E0','3B','4D','D7','62','A6','F1','08','18','28','78','88','83','9E','B9','D0','6B','BD','DC','7F','81','98','B3','CE','49','DB','76','9A','B5','C4','57','F9','10','30','50','F0','0B','1D','27','69','BB','D6','61','A3','FE','19','2B','7D','87','92','AD','EC','2F','71','93','AE','E9','20','60','A0','FB','16','3A','4E','D2','6D','B7','C2','5D','E7','32','56','FA','15','3F','41','C3','5E','E2','3D','47','C9','40','C0','5B','ED','2C','74','9C','BF','DA','75','9F','BA','D5','64','AC','EF','2A','7E','82','9D','BC','DF','7A','8E','89','80','9B','B6','C1','58','E8','23','65','AF','EA','25','6F','B1','C8','43','C5','54','FC','1F','21','63','A5','F4','07','09','1B','2D','77','99','B0','CB','46','CA','45','CF','4A','DE','79','8B','86','91','A8','E3','3E','42','C6','51','F3','0E','12','36','5A','EE','29','7B','8D','8C','8F','8A','85','94','A7','F2','0D','17','39','4B','DD','7C','84','97','A2','FD','1C','24','6C','B4','C7','52','F6','01']
L_table = ['**','00','19','01','32','02','1A','C6','4B','C7','1B','68','33','EE','DF','03','64','04','E0','0E','34','8D','81','EF','4C','71','08','C8','F8','69','1C','C1','7D','C2','1D','B5','F9','B9','27','6A','4D','E4','A6','72','9A','C9','09','78','65','2F','8A','05','21','0F','E1','24','12','F0','82','45','35','93','DA','8E','96','8F','DB','BD','36','D0','CE','94','13','5C','D2','F1','40','46','83','38','66','DD','FD','30','BF','06','8B','62','B3','25','E2','98','22','88','91','10','7E','6E','48','C3','A3','B6','1E','42','3A','6B','28','54','FA','85','3D','BA','2B','79','0A','15','9B','9F','5E','CA','4E','D4','AC','E5','F3','73','A7','57','AF','58','A8','50','F4','EA','D6','74','4F','AE','E9','D5','E7','E6','AD','E8','2C','D7','75','7A','EB','16','0B','F5','59','CB','5F','B0','9C','A9','51','A0','7F','0C','F6','6F','17','C4','49','EC','D8','43','1F','2D','A4','76','7B','B7','CC','BB','3E','5A','FB','60','B1','86','3B','52','A1','6C','AA','55','29','9D','97','B2','87','90','61','BE','DC','FC','BC','95','CF','CD','37','3F','5B','D1','53','39','84','3C','41','A2','6D','47','14','2A','9E','5D','56','F2','D3','AB','44','11','92','D9','23','20','2E','89','B4','7C','B8','26','77','99','E3','A5','67','4A','ED','DE','C5','31','FE','18','0D','63','8C','80','C0','F7','70','07']

#Substitute bytes:
# We basically have alook up table: 16x16
# We use first 4 bytes as row number and next 4 bytes as column number.
# we look at the resulting value in the lookup table and substitute it in place of the word.
def sub_bytes(byte_matrix):
    result_matrix = []
    for byte_row in byte_matrix:
        temp_row = []
        for byte in byte_row:
            row = int(byte[0:6],2)
            col = int('0b' + byte[6:],2)
            temp_row.append("0b"+bin(int(S_table[row*16 + col],16))[2:].zfill(8))
            #table is a list of list of binary string (i.e b'ssf' format)
        result_matrix.append(temp_row)
    return result_matrix

#Shift Word:
#Shift the byte in each row the row's index number of times to the left.
def shift_word(byte_matrix):
    result_matrix = []
    for i in range(4):
        row = byte_matrix[i]
        result_matrix.append(row[i:] + row[:i])
    return result_matrix

def custom_dot(byte_1,byte_2):
    #Algorithm for byte wise dot product in Galois Field:
    #1)Lookup L(byte_1) and L(byte_2)
    #2)Add the two lookup table values we got above
    #3)if the result is greater than FF, then subtract FF from the result
    #4)The E_table(Result) is the dot product required--- Result -  we got above
    int_byte_1 = int(byte_1,2)
    int_byte_2 = int(byte_2,2)
    if int_byte_1 == 1:
        return byte_2
    elif int_byte_2 == 1:
        return byte_1
    elif (int_byte_1 == 0) or (int_byte_2 == 0):
        return '0b00000000'
    else:
        L_byte_1 = L_table[int_byte_1] #hex form
        L_byte_2 = L_table[int_byte_2] #hex form
        sum_byte = int(L_byte_1,16) + int(L_byte_2,16)
        if sum_byte > 255:
            sum_byte -= 255
        return '0b'+bin(int(E_table[sum_byte],16))[2:].zfill(8)

def mix_col(byte_matrix):
    matrix = [["0b00000010","0b00000011","0b00000001","0b00000001"],["0b00000001","0b00000010","0b00000011","0b00000001"],["0b00000001","0b00000001","0b00000010","0b00000011"],["0b00000011","0b00000001","0b00000001","0b00000010"]]
    result_matrix = []
    for i in range(4):
        result_matrix.append([bin(int(custom_dot(matrix[i][0],byte_matrix[0][0]),2) ^ int(custom_dot(matrix[i][1],byte_matrix[1][0]),2) ^ int(custom_dot(matrix[i][2],byte_matrix[2][0]),2) ^ int(custom_dot(matrix[i][3],byte_matrix[3][0]),2)), bin(int(custom_dot(matrix[i][0],byte_matrix[0][1]),2) ^ int(custom_dot(matrix[i][1],byte_matrix[1][1]),2) ^ int(custom_dot(matrix[i][2],byte_matrix[2][1]),2) ^ int(custom_dot(matrix[i][3],byte_matrix[3][1]),2)), bin(int(custom_dot(matrix[i][0],byte_matrix[0][2]),2) ^ int(custom_dot(matrix[i][1],byte_matrix[1][2]),2) ^ int(custom_dot(matrix[i][2],byte_matrix[2][2]),2) ^ int(custom_dot(matrix[i][3],byte_matrix[3][2]),2)), bin(int(custom_dot(matrix[i][0],byte_matrix[0][3]),2) ^ int(custom_dot(matrix[i][1],byte_matrix[1][3]),2) ^ int(custom_dot(matrix[i][2],byte_matrix[2][3]),2) ^ int(custom_dot(matrix[i][3],byte_matrix[3][3]),2))])
    for i in range(4):
        for j in range(4):
            element = result_matrix[i][j]
            result_matrix[i][j] = '0b'+element[2:].zfill(8)
    return result_matrix

#Add round key:
#We take n'th word of key xor with n'th word of the state array.
def round_key(byte_matrix,key):
    key = ("0b"+bin(int(key,16))[2:].zfill(128))
    result_matrix = []
    key = key[2:]
    sub_key = ['0b'+key[i*8:(i+1)*8] for i in range(16)]
    #sub_key_num = [int(m,2) for m in sub_key]
    
    for i in range(4):
        sub_key_index = i
        row = byte_matrix[i]
        result_row = []
        for byte in row:
            result_row.append('0b'+bin(int(byte,2) ^ int(sub_key[sub_key_index],2))[2:].zfill(8))
            sub_key_index += 4
        result_matrix.append(result_row)
    return result_matrix

#key generation for 128 bit key
#cipher key is a one dimensional array format:r1r2r3...,in hex a1b5223bff437fde
rot_word = [["01","00","00","00"],["02","00","00","00"],["04","00","00","00"],["08","00","00","00"],["10","00","00","00"],["20","00","00","00"],["40","00","00","00"],["80","00","00","00"],["1b","00","00","00"],["36","00","00","00"]]
def key_gen(cipher_key):
    sub_keys = []
    sub_keys.append("0b"+bin(int(cipher_key[-32:-30],16))[2:].zfill(8)+bin(int(cipher_key[-30:-28],16))[2:].zfill(8)+bin(int(cipher_key[-28:-26],16))[2:].zfill(8)+bin(int(cipher_key[-26:-24],16))[2:].zfill(8)+bin(int(cipher_key[-24:-22],16))[2:].zfill(8)+bin(int(cipher_key[-22:-20],16))[2:].zfill(8)+bin(int(cipher_key[-20:-18],16))[2:].zfill(8)+bin(int(cipher_key[-18:-16],16))[2:].zfill(8)+bin(int(cipher_key[-16:-14],16))[2:].zfill(8)+bin(int(cipher_key[-14:-12],16))[2:].zfill(8)+bin(int(cipher_key[-12:-10],16))[2:].zfill(8)+bin(int(cipher_key[-10:-8],16))[2:].zfill(8)+bin(int(cipher_key[-8:-6],16))[2:].zfill(8)+bin(int(cipher_key[-6:-4],16))[2:].zfill(8)+bin(int(cipher_key[-4:-2],16))[2:].zfill(8)+bin(int(cipher_key[-2:],16))[2:].zfill(8))
    print(sub_keys)
    words = [sub_keys[0][-128:-96],sub_keys[0][-96:-64],sub_keys[0][-64:-32],sub_keys[0][-32:]]
    ##print("words:",words)
    for j in range(40):
        #word to be used for generation
        word = words[j+3]
        ##print("word:",word)
        #Rotation
        word = word[8:] + word[:8]
        ##print("after rotation:",word)
        #Substitution
        word = bin(int(S_table[int("0b"+word[:8],2)],16))[2:].zfill(8)+bin(int(S_table[int("0b"+word[8:16],2)],16))[2:].zfill(8)+bin(int(S_table[int("0b"+word[16:24],2)],16))[2:].zfill(8)+bin(int(S_table[int("0b"+word[24:32],2)],16))[2:].zfill(8)
        ##print("after substitution:",word)
        #Xor
        xor_word = words[j]
        ##print("xor_word:",xor_word)
        rt_word = rot_word[int(j/10)]
        word = bin(int("0b"+word,2)^int("0b"+xor_word,2)^int("0b"+bin(int(rt_word[0],16))[2:].zfill(8)+bin(int(rt_word[1],16))[2:].zfill(8)+bin(int(rt_word[2],16))[2:].zfill(8)+bin(int(rt_word[3],16))[2:].zfill(8),2))[2:].zfill(32)
        words.append(word)
    for i in range(10):
        k=(i+1)*4
        sub_keys.append("0b"+words[k]+words[k+1]+words[k+2]+words[k+3])
    return sub_keys

#AES Algorithm: 128bit text to 128bit cypher text
#Number of rounds: 10
#Round 1-9: Substitute Bytes ---> Shift Bytes ---> Mix Columns ---> Add Round Key (1 4 word key each)
#Round 10: Substitute Bytes ---> Shift Bytes ---> Add Round Key (1 4 word key)
#1 pre-round: Add Round Key (1 4 word key)

#######################################################

#data - address of the file to be encrypted if addr true, else the data
#cipher_key - a 128 bit key (16 bytes)

def encrypt(data,cipher_key,addr = True):
    encrypted_data = "0b"
    if addr:
        fb = open(data,"rb")    
        file_content = fb.read()
        fb.close()
    else:
        file_content = data
    n = 16
    #dividing to 128 bit chunks###
    data_chunks = [binascii.hexlify(file_content[i:i + n]).decode('utf-8') for i in range(0, file_content.__len__(), n)]
    print("data_chunk:",data_chunks)
    #key generation###############
    sub_keys = key_gen(cipher_key)
    ##############################
    for chunk in data_chunks:
        #data matrix preperation##
        data_matrix = []
        for i in range(4):
            row = []
            for j in range(4):
                k = (j*8) + (i*2)
                row.append("0b"+bin(int(chunk[k:k + 2],16))[2:].zfill(8))
            data_matrix.append(row)
        #pre round step###########
        state_matrix = round_key(data_matrix,sub_keys[0])
        for i in range(9):
            j = i+1
            state_matrix = round_key(mix_col(shift_word(sub_bytes(state_matrix))),sub_keys[j])
        state_matrix = round_key(shift_word(sub_bytes(state_matrix)),sub_keys[j])
        for i in range(4):
            for j in range(4):
                encrypted_data += state_matrix[j][i][2:]
        return hex(int(encrypted_data,2))

#key generation for 128 bit key
#cipher key is a one dimensional array format:r1r2r3...,in hex a1b5223bff437fde
rot_word = [["01","00","00","00"],["02","00","00","00"],["04","00","00","00"],["08","00","00","00"],["10","00","00","00"],["20","00","00","00"],["40","00","00","00"],["80","00","00","00"],["1b","00","00","00"],["36","00","00","00"]]
def key_gen(cipher_key):
    sub_keys = []
    sub_keys.append("0b"+bin(int(cipher_key[-32:-30],16))[2:].zfill(8)+bin(int(cipher_key[-30:-28],16))[2:].zfill(8)+bin(int(cipher_key[-28:-26],16))[2:].zfill(8)+bin(int(cipher_key[-26:-24],16))[2:].zfill(8)+bin(int(cipher_key[-24:-22],16))[2:].zfill(8)+bin(int(cipher_key[-22:-20],16))[2:].zfill(8)+bin(int(cipher_key[-20:-18],16))[2:].zfill(8)+bin(int(cipher_key[-18:-16],16))[2:].zfill(8)+bin(int(cipher_key[-16:-14],16))[2:].zfill(8)+bin(int(cipher_key[-14:-12],16))[2:].zfill(8)+bin(int(cipher_key[-12:-10],16))[2:].zfill(8)+bin(int(cipher_key[-10:-8],16))[2:].zfill(8)+bin(int(cipher_key[-8:-6],16))[2:].zfill(8)+bin(int(cipher_key[-6:-4],16))[2:].zfill(8)+bin(int(cipher_key[-4:-2],16))[2:].zfill(8)+bin(int(cipher_key[-2:],16))[2:].zfill(8))
    print(sub_keys)
    words = [sub_keys[0][-128:-96],sub_keys[0][-96:-64],sub_keys[0][-64:-32],sub_keys[0][-32:]]
    ##print("words:",words)
    for j in range(40):
        #word to be used for generation
        word = words[j+3]
        ##print("word:",word)
        #Rotation
        word = word[8:] + word[:8]
        ##print("after rotation:",word)
        #Substitution
        word = bin(int(S_table[int("0b"+word[:8],2)],16))[2:].zfill(8)+bin(int(S_table[int("0b"+word[8:16],2)],16))[2:].zfill(8)+bin(int(S_table[int("0b"+word[16:24],2)],16))[2:].zfill(8)+bin(int(S_table[int("0b"+word[24:32],2)],16))[2:].zfill(8)
        ##print("after substitution:",word)
        #Xor
        xor_word = words[j]
        ##print("xor_word:",xor_word)
        rt_word = rot_word[int(j/10)]
        word = bin(int("0b"+word,2)^int("0b"+xor_word,2)^int("0b"+bin(int(rt_word[0],16))[2:].zfill(8)+bin(int(rt_word[1],16))[2:].zfill(8)+bin(int(rt_word[2],16))[2:].zfill(8)+bin(int(rt_word[3],16))[2:].zfill(8),2))[2:].zfill(32)
        words.append(word)
    for i in range(10):
        k=(i+1)*4
        sub_keys.append("0b"+words[k]+words[k+1]+words[k+2]+words[k+3])
    return sub_keys

def encrypt(data,cipher_key,addr = True):
    encrypted_data = "0b"
    if addr:
        fb = open(data,"rb")    
        file_content = fb.read()
        fb.close()
    else:
        file_content = data
    n = 16
    #dividing to 128 bit chunks###
    data_chunks = [binascii.hexlify(file_content[i:i + n]).decode('utf-8') for i in range(0, file_content.__len__(), n)]
    print("data_chunk:",data_chunks)
    #key generation###############
    sub_keys = key_gen(cipher_key)
    ##############################
    for chunk in data_chunks:
        #data matrix preperation##
        data_matrix = []
        for i in range(4):
            row = []
            for j in range(4):
                k = (j*8) + (i*2)
                row.append("0b"+bin(int(chunk[k:k + 2],16))[2:].zfill(8))
            data_matrix.append(row)
        #pre round step###########
        state_matrix = round_key(data_matrix,sub_keys[0])
        for i in range(9):
            j = i+1
            state_matrix = round_key(mix_col(shift_word(sub_bytes(state_matrix))),sub_keys[j])
        state_matrix = round_key(shift_word(sub_bytes(state_matrix)),sub_keys[j])
        for i in range(4):
            for j in range(4):
                encrypted_data += state_matrix[j][i][2:]
        return hex(int(encrypted_data,2))
encrypt(b"\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34","2b7e151628aed2a6abf7158809cf4f3c",False)


# In[ ]:





# In[ ]:





# In[ ]:




