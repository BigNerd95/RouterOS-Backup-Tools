#!/usr/bin/env python3

# RouterOS Backup Tools by BigNerd95

import sys, os, struct
from random import randrange
from argparse import ArgumentParser, FileType
from Crypto.Cipher import ARC4
from Crypto.Hash import SHA

# RouterOS constants
MAGIC_ENCRYPTED = 0x7291A8EF
MAGIC_PLAINTEXT = 0xB1A1AC88
RC4_SKIP = 0x300

#####################
# support functions #
#####################

def get_header(input_file):
    input_file.seek(0, 0)
    data = input_file.read(8)
    header = struct.unpack('<II', data)
    return header[0], header[1]

def get_salt(input_file):
    input_file.seek(8, 0)
    data = input_file.read(32)
    salt = struct.unpack('<32s', data)
    return salt[0]

def get_magic_check(input_file):
    input_file.seek(40, 0)
    data = input_file.read(4)
    magic_check = struct.unpack('<4s', data)
    return magic_check[0]

def check_password(cipher, magic_check):
    data = cipher.decrypt(magic_check)
    decrypted_magic_check = struct.unpack('<I', data)
    return decrypted_magic_check[0] == MAGIC_PLAINTEXT

def make_salt(size):
    return bytes([randrange(256) for _ in range(size)])

def setup_cipher(salt, password):
    key = SHA.new(salt + bytes(password, 'ascii')).digest()
    cipher = ARC4.new(key)
    cipher.encrypt(bytes(RC4_SKIP)) # skip stream start
    return cipher

def extract_data(input_file):
    raw_len = input_file.read(4)
    if len(raw_len) != 4:
        raise EOFError('EOF')
    data_len = struct.unpack('<I', raw_len)[0]

    raw_data = input_file.read(data_len)
    if len(raw_data) != data_len:
        raise EOFError('EOF')
    return raw_data

def create_write_file(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)

def get_file_list(path):
    file_list = []

    original_path = os.getcwd()
    os.chdir(path)
    for root, dirs, files in os.walk("."):
        file_path = root.split(os.sep)[1:]
        file_path = '/'.join(file_path)
        if file_path:
            file_path += '/'
        for file in files:
            # check if both idx and dat files exist
            if file.endswith(".idx") and file[:-3] + "dat" in files:
                file_list.append(file_path + file[:-4])
    os.chdir(original_path)

    return file_list

def write_data(output_file, data):
    data_len = struct.pack('<I', len(data))
    output_file.write(data_len)
    output_file.write(data)

##################
# core functions #
##################

def decrypt_backup(input_file, output_file, cipher):
    input_file.seek(44, 0) # skip magic, length, salt, magic_check
    output_file.seek(0, 0)
    magic = struct.pack('<I', MAGIC_PLAINTEXT)
    output_file.write(magic + bytes(4)) # magic, length offset

    while True:
        chunk = input_file.read(1024)
        if not chunk:
            break
        output_file.write(cipher.decrypt(chunk))

    length = struct.pack('<I', output_file.tell()) # length
    output_file.seek(4, 0)
    output_file.write(length)

def encrypt_backup(input_file, output_file, cipher, salt):
    input_file.seek(8, 0) # skip magic, length
    output_file.seek(0, 0)
    magic = struct.pack('<I', MAGIC_ENCRYPTED)
    output_file.write(magic + bytes(4) + salt) # magic, length offset, salt

    magic_check = struct.pack('<I', MAGIC_PLAINTEXT)
    output_file.write(cipher.encrypt(magic_check))

    while True:
        chunk = input_file.read(1024)
        if not chunk:
            break
        output_file.write(cipher.encrypt(chunk))

    length = struct.pack('<I', output_file.tell()) # length
    output_file.seek(4, 0)
    output_file.write(length)

def unpack_files(input_file, file_length, path):
    count = 0
    input_file.seek(8, 0) # skip magic, length

    path = os.path.join(path, '')
    if os.path.exists(path):
        print("Directory", os.path.basename(path) , "already exists, cannot extract!")
        return count

    while input_file.tell() < file_length:
        try:
            name = extract_data(input_file).decode('ascii')
            idx = extract_data(input_file)
            dat = extract_data(input_file)

            create_write_file(path + name + '.idx', idx)
            create_write_file(path + name + '.dat', dat)

            count += 1
        except EOFError:
            print("Unexpected End of File!")
            break
    return count

def pack_files(path, file_names, output_file):
    output_file.seek(0, 0)
    magic = struct.pack('<I', MAGIC_PLAINTEXT)
    output_file.write(magic + bytes(4)) # magic, length offset

    path = os.path.join(path, '')
    for name in file_names:
        with open(path + name + '.idx', "rb") as idx_file:
            idx = idx_file.read()
        with open(path + name + '.dat', "rb") as dat_file:
            dat = dat_file.read()

        write_data(output_file, name.encode('ascii'))
        write_data(output_file, idx)
        write_data(output_file, dat)

    length = struct.pack('<I', output_file.tell()) # length
    output_file.seek(4, 0)
    output_file.write(length)

# parallel bruteforcing function
def brute(namespace, salt, magic_check, password):
    global found # init in caller function "bruteforce"

    if not found:
        cipher = setup_cipher(salt, password.strip())
        if check_password(cipher, magic_check):
            found = True
            namespace.found = found
            namespace.password = password

        # communication drastically drop down the performance, so we make it only once each 1000 iterations
        global counter # init in caller function "bruteforce"
        counter += 1
        if counter == 1000: # <-- increase 1000 if all CPU are not at 100%
            counter = 0
            found = namespace.found

##################
# main functions #
##################

def info(input_file):
    print('** Backup Info **')
    magic, length = get_header(input_file)

    if magic == MAGIC_ENCRYPTED:
        print("RouterOS Encrypted Backup")
        print("Length:", length, "bytes")
        salt = get_salt(input_file)
        print("Salt (hex):", salt.hex())
        magic_check = get_magic_check(input_file)
        print("Magic Check (hex):", magic_check.hex())

    elif magic == MAGIC_PLAINTEXT:
        print("RouterOS Plaintext Backup")
        print("Length:", length, "bytes")

    else:
        print("Invalid file!")

    input_file.close()

def decrypt(input_file, output_file, password):
        print('** Decrypt Backup **')
        magic, length = get_header(input_file)

        if magic == MAGIC_ENCRYPTED:
            print("RouterOS Encrypted Backup")
            print("Length:", length, "bytes")
            salt = get_salt(input_file)
            print("Salt (hex):", salt.hex())
            magic_check = get_magic_check(input_file)
            print("Magic Check (hex):", magic_check.hex())

            cipher = setup_cipher(salt, password)

            if check_password(cipher, magic_check):
                print("Correct password!")
                print("Decrypting...")
                decrypt_backup(input_file, output_file, cipher)
                print("Decrypted correctly")
            else:
                print("Wrong password!")
                print("Cannot decrypt!")

        elif magic == MAGIC_PLAINTEXT:
            print("RouterOS Plaintext Backup")
            print("No decryption needed!")

        else:
            print("Invalid file!")
            print("Cannot decrypt!")

        input_file.close()
        output_file.close()

def encrypt(input_file, output_file, password):
        print('** Encrypt Backup **')
        magic, length = get_header(input_file)

        if magic == MAGIC_ENCRYPTED:
            print("RouterOS Encrypted Backup")
            print("No encryption needed!")

        elif magic == MAGIC_PLAINTEXT:
            print("RouterOS Plaintext Backup")
            print("Length:", length, "bytes")
            salt = make_salt(32)
            print("Generated Salt (hex):", salt.hex())

            cipher = setup_cipher(salt, password)

            print("Encrypting...")
            encrypt_backup(input_file, output_file, cipher, salt)
            print("Encrypted correctly")

        else:
            print("Invalid file!")
            print("Cannot encrypt!")

        input_file.close()
        output_file.close()

def unpack(input_file, unpack_directory):
        print('** Unpack Backup **')
        magic, length = get_header(input_file)

        if magic == MAGIC_ENCRYPTED:
            print("RouterOS Encrypted Backup")
            print("Cannot unpack encrypted backup!")
            print("Decrypt backup first!")

        elif magic == MAGIC_PLAINTEXT:
            print("RouterOS Plaintext Backup")
            print("Length:", length, "bytes")

            print("Extracting backup...")
            files_num = unpack_files(input_file, length, unpack_directory)
            if files_num > 0:
                print("Wrote", files_num, "files pair in:", unpack_directory)

        else:
            print("Invalid file!")
            print("Cannot unpack!")

        input_file.close()

def pack(output_file, pack_directory):
        print('** Pack Backup **')

        file_names = get_file_list(pack_directory)
        if len(file_names) > 0:
            print("Creating plaintext backup with", len(file_names), "files pair...")
            pack_files(pack_directory, file_names, output_file)
            print("Done!")
        else:
            print("Error! No IDX and DAT files found!")

        output_file.close()

def bruteforce(input_file, wordlist_file, parallel=False):
        print('** Bruteforce Backup Password **')
        magic, length = get_header(input_file)

        if magic == MAGIC_ENCRYPTED:
            print("RouterOS Encrypted Backup")
            print("Length:", length, "bytes")
            salt = get_salt(input_file)
            print("Salt (hex):", salt.hex())
            magic_check = get_magic_check(input_file)
            print("Magic Check (hex):", magic_check.hex())

            if parallel:

                print("Parallel brute forcing...")

                from multiprocessing import Pool, Manager
                from functools import partial

                global counter
                global found
                counter = 0
                found = False

                namespace = Manager().Namespace()
                namespace.found = found
                namespace.password = None

                Pool().map(partial(brute, namespace, salt, magic_check), wordlist_file)

                found = namespace.found
                password = namespace.password

            else:

                print("Brute forcing...")

                found = False
                for password in wordlist_file:
                    cipher = setup_cipher(salt, password.strip())
                    if check_password(cipher, magic_check):
                        found = True
                        break

            if found:
                print("Password found:", password)
            else:
                print("Password NOT found")

        elif magic == MAGIC_PLAINTEXT:
            print("RouterOS Plaintext Backup")
            print("No decryption needed!")

        else:
            print("Invalid file!")
            print("Cannot decrypt!")

        input_file.close()
        wordlist_file.close()

def parse_cli():
    parser = ArgumentParser(description='** RouterOS Backup Tools by BigNerd95 **')
    subparser = parser.add_subparsers(dest='subparser_name')

    infoParser = subparser.add_parser('info', help='Backup info')
    infoParser.add_argument('-i', '--input', required=True, metavar='INPUT_FILE', type=FileType('rb'))

    decryptParser = subparser.add_parser('decrypt', help='Decrypt backup')
    decryptParser.add_argument('-i', '--input', required=True, metavar='INPUT_FILE', type=FileType('rb'))
    decryptParser.add_argument('-o', '--output', required=True, metavar='OUTPUT_FILE', type=FileType('wb'))
    decryptParser.add_argument('-p', '--password', required=True, metavar='PASSWORD')

    encryptParser = subparser.add_parser('encrypt', help='Encrypt backup')
    encryptParser.add_argument('-i', '--input', required=True, metavar='INPUT_FILE', type=FileType('rb'))
    encryptParser.add_argument('-o', '--output', required=True, metavar='OUTPUT_FILE', type=FileType('wb'))
    encryptParser.add_argument('-p', '--password', required=True, metavar='PASSWORD')

    unpackParser = subparser.add_parser('unpack', help='Unpack backup')
    unpackParser.add_argument('-i', '--input', required=True, metavar='INPUT_FILE', type=FileType('rb'))
    unpackParser.add_argument('-d', '--directory', required=True, metavar='UNPACK_DIRECTORY')

    packParser = subparser.add_parser('pack', help='Unpack backup')
    packParser.add_argument('-d', '--directory', required=True, metavar='PACK_DIRECTORY')
    packParser.add_argument('-o', '--output', required=True, metavar='OUTPUT_FILE', type=FileType('wb'))

    bruteforceParser = subparser.add_parser('bruteforce', help='Bruteforce backup password')
    bruteforceParser.add_argument('-i', '--input', required=True, metavar='INPUT_FILE', type=FileType('rb'))
    bruteforceParser.add_argument('-w', '--wordlist', required=True, metavar='WORDLIST_FILE', type=FileType('rt'))
    bruteforceParser.add_argument('-p', '--parallel', action='store_true', help='Use all CPU cores')

    if len(sys.argv) < 2:
        parser.print_help()

    return parser.parse_args()

def main():
    args = parse_cli()
    if args.subparser_name == 'info':
        info(args.input)
    elif args.subparser_name == 'decrypt':
        decrypt(args.input, args.output, args.password)
    elif args.subparser_name == 'encrypt':
        encrypt(args.input, args.output, args.password)
    elif args.subparser_name == 'unpack':
        unpack(args.input, args.directory)
    elif args.subparser_name == 'pack':
        pack(args.output, args.directory)
    elif args.subparser_name == 'bruteforce':
        bruteforce(args.input, args.wordlist, args.parallel)

if __name__ == '__main__':
    main()
