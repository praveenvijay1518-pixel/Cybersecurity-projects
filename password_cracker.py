Python 3.12.1 (tags/v3.12.1:2305ca5, Dec  7 2023, 22:03:25) [MSC v.1937 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license()" for more information.
import hashlib
import itertools
import time
import sys


# --------------------------
# HASH TYPE DETECTION
# --------------------------
def detect_hash_type(hash_value):
    hash_len = len(hash_value)

    if hash_len == 32:
        return "md5"
    elif hash_len == 40:
        return "sha1"
    elif hash_len == 64:
        return "sha256"
    elif hash_len == 128:
        return "sha512"
    else:
        return None


# --------------------------
# HASHING FUNCTION
# --------------------------
def hash_word(word, algo):
    h = hashlib.new(algo)
    h.update(word.encode())
    return h.hexdigest()


# --------------------------
# DICTIONARY ATTACK
# --------------------------
def dictionary_attack(hash_value, algo, wordlist_path):
    print("\n[+] Starting Dictionary Attack...")

    try:
        with open(wordlist_path, "r", errors="ignore") as f:
            words = f.readlines()
    except FileNotFoundError:
        print("[-] Wordlist not found!")
        return None, 0

    start_time = time.time()

    for word in words:
        word = word.strip()
        if hash_word(word, algo) == hash_value:
            return word, time.time() - start_time

    return None, time.time() - start_time


# --------------------------
# BRUTE FORCE ATTACK
# --------------------------
def brute_force_attack(hash_value, algo, max_length=4,
                       char_set="abcdefghijklmnopqrstuvwxyz0123456789"):
    print("\n[+] Starting Brute-force Attack...")
    start = time.time()

    for length in range(1, max_length + 1):
        for combo in itertools.product(char_set, repeat=length):
            attempt = ''.join(combo)

            if hash_word(attempt, algo) == hash_value:
                return attempt, time.time() - start

    return None, time.time() - start


# --------------------------
# MAIN PROGRAM
# --------------------------
def main():
    print("\n========== Hashed Password Cracker ==========")

    hash_value = input("\nEnter the hashed password: ").strip().lower()
    algo = detect_hash_type(hash_value)

    if algo is None:
...         print("[-] Unknown or unsupported hash type!")
...         sys.exit()
... 
...     print(f"[+] Detected Hash Type: {algo.upper()}")
... 
...     print("\nChoose attack method:")
...     print("1) Dictionary Attack")
...     print("2) Brute Force Attack (slow)")
... 
...     choice = input("\nEnter choice (1/2): ")
... 
...     if choice == "1":
...         wordlist_path = input("Enter wordlist path (e.g. wordlist.txt): ")
...         result, duration = dictionary_attack(hash_value, algo, wordlist_path)
... 
...         if result:
...             print(f"\n[✓] Password Found: {result}")
...         else:
...             print("\n[X] Password not found in dictionary!")
... 
...         print(f"Time Taken: {duration:.2f} seconds")
... 
...     elif choice == "2":
...         max_len = int(input("Max password length (recommended 4): "))
...         result, duration = brute_force_attack(hash_value, algo, max_len)
... 
...         if result:
...             print(f"\n[✓] Password Found: {result}")
...         else:
...             print("\n[X] Password not found by brute force!")
... 
...         print(f"Time Taken: {duration:.2f} seconds")
... 
...     else:
...         print("Invalid choice!")
... 
... 
... if __name__ == "__main__":
...     main()
