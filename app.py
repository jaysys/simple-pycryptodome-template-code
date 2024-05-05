from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import sqlite3
import os
from dotenv import dotenv_values

# .env 파일 로드
env_values = dotenv_values(os.path.join('config', '.env'))

# 데이터베이스 연결
conn = sqlite3.connect('encrypted_data.db')
cursor = conn.cursor()

# 테이블 생성
cursor.execute('''CREATE TABLE IF NOT EXISTS personal_info (
                    id INTEGER PRIMARY KEY,
                    name TEXT,
                    encrypted_ssn BLOB,
                    key_ BLOB,
                    iv_ BLOB
                )''')

# 사용자로부터 비밀번호 입력 받음
password = env_values.get("PASSWORD")
print("pw:", password)
if not password:
    raise ValueError("비밀번호가 .env 파일에 설정되지 않았습니다.")

salt = get_random_bytes(16)
print("salt:", salt)

# 비밀번호를 기반으로 키와 IV 생성
def generate_key_iv(password, salt):
    key_iv = PBKDF2(password, salt, dkLen=32, count=1000000)
    return key_iv[:16], key_iv[16:]

# 비밀번호를 기반으로 키와 IV 생성
key, iv = generate_key_iv(password.encode(), salt)
print("key,iv",key,iv)

# 데이터를 AES로 암호화
def encrypt_data(data, key, iv):
    # 패딩 추가
    if len(data) % 16 != 0:
        data += b'\0' * (16 - len(data) % 16)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(data)
    return cipher_text

# 암호화한 데이터를 저장한다.  
if True: # False로 바꾸고 읽기만 테스트 할 수 있게 if만 넣어놨음.
    name = input("이름을 입력하세요: ")
    ssn = input("주민등록번호를 입력하세요: ")
    encrypted_ssn = encrypt_data(ssn.encode(), key, iv)

    cursor.execute("INSERT INTO personal_info (name, encrypted_ssn, key_, iv_) VALUES (?, ?, ?, ?)", (name, encrypted_ssn, key, iv))
    conn.commit()

# 데이터를 AES로 복호화
def decrypt_data(cipher_text, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = cipher.decrypt(cipher_text)
    return plain_text.rstrip(b'\0')


# 데이터 조회 및 복호화
cursor.execute("SELECT * FROM personal_info")
rows = cursor.fetchall()
import pprint
pprint.pprint(rows)

for row in rows:
    decrypted_ssn = decrypt_data(row[2], key=row[3], iv=row[4]).decode()
    print("ID:", row[0])
    print("Name:", row[1])
    print("Decrypted SSN:", decrypted_ssn)

# 데이터베이스 연결 종료
conn.close()

