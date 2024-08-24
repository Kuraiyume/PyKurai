import hashlib
import threading
import sys

banner = """
 ██████╗  ██████╗  ██████╗  ██████╗
██╔═████╗██╔═████╗██╔═████╗██╔════╝
██║██╔██║██║██╔██║██║██╔██║███████╗
████╔╝██║████╔╝██║████╔╝██║██╔═══██╗
╚██████╔╝╚██████╔╝╚██████╔╝╚██████╔╝    Veilwr4ith
 ╚═════╝  ╚═════╝  ╚═════╝  ╚═════╝
"""
HASH_NAMES = {
    'blake2b', 'blake2s', 'md5', 'sha1', 'sha224', 'sha256', 'sha384',
    'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'sha512'
}

def process_chunk(start_line, end_line, hash_to_crack, wordlist_path, hash_fn, result, lock, found_event, verbose):
    try:
        with open(wordlist_path, 'rb') as wordlist_file:
            for idx, line in enumerate(wordlist_file, start=1):
                if start_line <= idx <= end_line:
                    if found_event.is_set():
                        return
                    try:
                        word = line.decode('utf-8').strip()
                    except UnicodeDecodeError:
                        continue
                    hashed_word = hash_fn(word.encode()).hexdigest()
                    if verbose:
                        print(f"[*] Trying: {word}")
                    if hashed_word == hash_to_crack:
                        with lock:
                            if not result[0]:
                                result[0] = word
                                if verbose:
                                    print(f"[+] Password found: {word}")
                                found_event.set()
                        return
    except Exception as e:
        print(f'[!] An error occurred while processing a chunk: {e}')

def crack_hash(hash_to_crack, wordlist_path, hash_type='md5', verbose=False, num_threads=4):
    if hash_type not in HASH_NAMES:
        raise ValueError(f'[!] Invalid hash type: {hash_type}. Supported types are: {HASH_NAMES}')
    hash_fn = getattr(hashlib, hash_type, None)
    if hash_fn is None:
        raise ValueError(f'[!] Hash function not found for type: {hash_type}')
    try:
        with open(wordlist_path, 'rb') as wordlist_file:
            total_lines = sum(1 for _ in wordlist_file)
            wordlist_file.seek(0)
            if verbose:
                print(f"[*] Cracking hash {hash_to_crack} using {hash_type} with a list of {total_lines} words.")
            lines_per_thread = total_lines // num_threads
            threads = []
            result = [None]
            lock = threading.Lock()
            found_event = threading.Event()
            for i in range(num_threads):
                start_line = i * lines_per_thread + 1
                end_line = (i + 1) * lines_per_thread if i < num_threads - 1 else total_lines
                thread = threading.Thread(target=process_chunk, args=(start_line, end_line, hash_to_crack, wordlist_path, hash_fn, result, lock, found_event, verbose))
                thread.start()
                threads.append(thread)
            for thread in threads:
                thread.join()
            if verbose and result[0] is None:
                print("[!] Password not found.")
            return result[0]
    except FileNotFoundError:
        print(f'[!] Error: The file {wordlist_path} was not found.')
    except Exception as e:
        print(f'[!] An unexpected error occurred: {e}')
    return None

def main():
    import argparse
    print(banner)
    parser = argparse.ArgumentParser(description='Crack hashes supported by hashlib')
    parser.add_argument('hash', help='The hash to crack.')
    parser.add_argument('wordlist', help='The path to the wordlist.')
    parser.add_argument('--hash-type', help='The hash type to use.', default='md5')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output.')
    parser.add_argument('--threads', type=int, help='Number of threads to use.', default=4)
    args = parser.parse_args()
    print()
    result = crack_hash(args.hash, args.wordlist, args.hash_type, verbose=args.verbose, num_threads=args.threads)
    if not args.verbose and result is None:
        print("[!] Password not found.")
    elif result is None:
        print("[!] Password not found.")

if __name__ == "__main__":
    main()
