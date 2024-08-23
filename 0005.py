import pikepdf
import logging
import time
import argparse
import sys
import threading
from queue import Queue
banner = """
 ██████╗  ██████╗  ██████╗ ███████╗
██╔═████╗██╔═████╗██╔═████╗██╔════╝
██║██╔██║██║██╔██║██║██╔██║███████╗
████╔╝██║████╔╝██║████╔╝██║╚════██║
╚██████╔╝╚██████╔╝╚██████╔╝███████║  Veilwr4ith
 ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝
"""
logging.basicConfig(level=logging.INFO, format='%(message)s')

def try_password(pdf_path, password, result_queue):
    try:
        with pikepdf.open(pdf_path, password=password) as pdf:
            result_queue.put(password)
            return True
    except pikepdf._core.PasswordError:
        return False
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return False

def worker(pdf_path, passwords, result_queue, thread_id):
    for password in passwords:
        logging.info(f"Thread-{thread_id} Trying: {password}")
        if try_password(pdf_path, password, result_queue):
            break

def main():
    print(banner)
    parser = argparse.ArgumentParser(description="PDF Password Cracker")
    parser.add_argument("pdf_path", help="Path to the protected PDF file")
    parser.add_argument("wordlist", help="Path to the wordlist file")
    parser.add_argument("--exit-on-success", action="store_true", help="Exit the script as soon as the password is found")
    parser.add_argument("--output-file", help="File to save found passwords")
    parser.add_argument("--threads", type=int, default=4, help="Number of concurrent threads to use")
    args = parser.parse_args()
    pdf_path = args.pdf_path
    wordlist_path = args.wordlist
    exit_on_success = args.exit_on_success
    output_file = args.output_file
    num_threads = args.threads
    try:
        with open(wordlist_path) as f:
            passwords = [line.strip() for line in f]
    except FileNotFoundError:
        logging.error(f"Error: {wordlist_path} file not found.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error reading {wordlist_path}: {e}")
        sys.exit(1)
    start_time = time.time()
    result_queue = Queue()
    chunk_size = len(passwords) // num_threads
    threads = []
    for i in range(num_threads):
        start_index = i * chunk_size
        end_index = None if i == num_threads - 1 else (i + 1) * chunk_size
        thread = threading.Thread(target=worker, args=(pdf_path, passwords[start_index:end_index], result_queue, i + 1))
        threads.append(thread)
        thread.start()
    found_password = None
    for thread in threads:
        thread.join()
        if not result_queue.empty():
            found_password = result_queue.get()
            break
    if found_password:
        logging.info(f"[+] Password found: {found_password}")
        if output_file:
            with open(output_file, 'a') as f:
                f.write(f"{found_password}\n")
        if exit_on_success:
            sys.exit(0)
    else:
        logging.info("No password found.")
    end_time = time.time()
    elapsed_time = end_time - start_time
    logging.info(f"Finished in {elapsed_time:.2f} seconds.")

if __name__ == "__main__":
    main()
