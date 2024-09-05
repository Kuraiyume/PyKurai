import zipfile
import sys
import threading
import logging
from queue import Queue, Empty

banner = """
   ___   ___   ___  _  _
  / _ \ / _ \ / _ \| || |
 | | | | | | | | | | || |_
 | | | | | | | | | |__   _|
 | |_| | |_| | |_| |  | |
  \___/ \___/ \___/   |_|   Kuraiyume
"""
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
password_found = threading.Event()

def try_password(zip_file, password_queue):
    while not password_queue.empty():
        if password_found.is_set():
            return
        password = password_queue.get()
        password_str = password.decode(errors='ignore').strip()
        print(f"[*] Trying: {password_str}")
        try:
            zip_file.extractall(pwd=password)
        except RuntimeError as e:
            if 'Bad password' in str(e):
                pass
            else:
                pass
        except Exception as e:
            pass
        else:
            print(f"[+] Password found: {password_str}")
            password_found.set()
            return
        finally:
            password_queue.task_done()

def crack_zip_password(zip_path, wordlist_path, num_threads):
    try:
        zip_file = zipfile.ZipFile(zip_path)
    except Exception as e:
        logging.error(f"Error opening zip file: {e}")
        sys.exit(1)
    try:
        with open(wordlist_path, "rb") as wordlist:
            passwords = wordlist.readlines()
    except Exception as e:
        logging.error(f"Error opening wordlist: {e}")
        sys.exit(1)
    total_words = len(passwords)
    logging.info(f"Total passwords to test: {total_words}")
    password_queue = Queue()
    for password in passwords:
        password_queue.put(password.strip())
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=try_password, args=(zip_file, password_queue))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    if not password_found.is_set():
        logging.info("Password not found, try another wordlist.")

if __name__ == "__main__":
    print(banner)
    if len(sys.argv) != 4:
        print("[*] Usage: python3 script.py <zipfile> <wordlist> <num_threads>")
        sys.exit(1)
    zip_path = sys.argv[1]
    wordlist_path = sys.argv[2]
    try:
        num_threads = int(sys.argv[3])
        if num_threads <= 0:
            raise ValueError("[-] Number of threads must be a positive integer.")
    except ValueError as e:
        logging.info(f"[-] Invalid number of threads: {e}")
        sys.exit(1)
    crack_zip_password(zip_path, wordlist_path, num_threads)
