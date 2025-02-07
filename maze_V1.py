import re
import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

print('<------ MAZE_V1 加密字典生成工具 ------>')

user_option = 0

def AES_Encryption(clear_text,key,iv):
    b_key = key.encode('utf-8')
    b_iv = iv.encode('utf-8')
    b_clear_text = clear_text.encode('utf-8')

    padded_Data = pad(b_clear_text,AES.block_size)
    cipher = AES.new(b_key,AES.MODE_CBC,b_iv)
    encypted_Data = cipher.encrypt(padded_Data)

    final_cipher_string = base64.b64decode(base64.b64encode(encypted_Data).decode('utf-8'))
    final_cipher_string_b64 = base64.b64encode(encypted_Data).decode('utf-8')
    print("加密结果:",final_cipher_string)
    print("带base64加密结果:",final_cipher_string_b64)
    return final_cipher_string_b64
    
#  1234567890123456
#  m4R0rUAW4REnW0XPhHfDCw==

def AES_Decryption(b64_encrypted_text,key,iv):
    #b_b64_encrypted_text = b64_encrypted_text.encode('utf-8')
    b_key = key.encode('utf-8')
    b_iv = iv.encode('utf-8')

    encrypted_text = base64.b64decode(b64_encrypted_text)
    cipher = AES.new(b_key,AES.MODE_CBC,b_iv)
    decrypted_text = cipher.decrypt(encrypted_text)
    final_decrypted_text = unpad(decrypted_text,AES.block_size).decode('utf-8')
    print("解密结果:",final_decrypted_text)



def encrypt_File_Handle(file_name,key,iv):
    with open(file_name,'r') as file:
        with open("EncryptedDic.txt",'w') as new_file:
            lines = file.readlines()
            for line in lines:
                 line = line.strip()
                 new_line = AES_Encryption(line,key,iv)
                 new_file.write(new_line)
                 new_file.write('\n')
                 
    print("新生成的字典名:EncryptedDic.txt")


if __name__ == "__main__":
    print('选择加解密形式:')
    print('1.AES CBC PKCS5Padding.')
    #print('1.加密')
    #print('2.解密')
    user_option = input("选项:")
    if user_option == '1':
        print('1.加密')
        print('2.解密')
        en_option = input("选项:")
        if en_option == '1':
            print('1.单行数据加密')
            print('2.单个文件加密')
            sub_en_option_1 = input("选项:")
            if sub_en_option_1 == '1':
                clearString = input('请输入明文字符串:')
                key = input('请输入AES key:')
                iv = input('请输入AES iv:')
                AES_Encryption(clearString,key,iv)
            elif sub_en_option_1 == '2':
                filename = input('请输入文件名:')
                key = input('请输入AES key:')
                iv = input('请输入AES iv:')
                encrypt_File_Handle(filename,key,iv)
        elif en_option == '2':
             #sub_user_option_2 = input("选项")
             #if sub_user_option_2 == '1':
            encryptedString = input('请输入加密字符串:')
            key = input('请输入AES key:')
            iv = input('请输入AES iv:')
            AES_Decryption(encryptedString,key,iv)
    