import hashlib
import requests


def password_leak(password):
    
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    
    prefix = sha1[:5]
    suffix = sha1[5:]
    
    
    url = f'https://api.pwnedpasswords.com/range/{prefix}'
    response = requests.get(url)
    
    if response.status_code == 200:
        
        hashes = response.text.splitlines()
        
        
        for hash in hashes:
            hash_suffix, count = hash.split(':')
            if hash_suffix == suffix:
                return True, count  
        
        
        return False, None
    else:
        print("[!] Error checking password")
        return False, None


def user_password():
    while True:
        password = input("Enter a password to check if it is secure: ")
        
       
        leaked, breach_count = password_leak(password)
        
        if leaked:
            print(f"[!] The password has been found in {breach_count} breaches! Please choose a different password.")
        else:
            print("[+] The password is safe and not found in any known breaches.")
            break


def main():
    
    print("""
    ******    *****   ****   ****        *****   *   *    *****    *****   *    *
    *    *   *     *  *      *           *       *   *    *        *       *  *
    ******    *****   ****   ****        *       *****    *****    *       **
    *        *     *     *      *        *       *   *    *        *       *  *
    *        *     *  ****   ****        *****   *   *    *****    *****   *     *
    """)




    print("[+] Welcome to the Secure Password Checker!")
    user_password()

if __name__ == "__main__":
    main()







