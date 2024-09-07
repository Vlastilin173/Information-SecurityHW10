import re
import hashlib

def check_password_complexity(password):
    if len(password) < 8:
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    return True

def hash_password(password):
    # перевод в хэш-значение алгоритм SHA-256
    sha256_hash = hashlib.sha256()
    sha256_hash.update(password.encode('utf-8'))
    return sha256_hash.hexdigest()
def main():
    password = input("Введите пароль: ")
    if check_password_complexity(password):
        hashed_password = hash_password(password)
        print(f"Успешно!")
        print(f"Хэш-значение пароля: {hashed_password}")
    else:
        print("Пароль не соответствует условиям.")

if __name__ == "__main__":
    main()