# RouterOS-Backup-Tools
Tools to encrypt/decrypt and pack/unpack RouterOS v6.13+ backup files

# Usage examples  

### Info
`./ROSbackup.py info -i MikroTik.backup`  

### Decrypt  
Convert an encrypted backup to a plaintext backup  
`./ROSbackup.py decrypt -i MikroTik-encrypted.backup -o MikroTik-plaintext.backup -p password`  

### Encrypt  
Convert a plaintext backup to an encrypted backup  
`./ROSbackup.py encrypt -i MikroTik-plaintext.backup -o MikroTik-encrypted.backup -p password`  

### Unpack  
Extract all IDX and DAT files from a plaintext backup in a given directory    
`./ROSbackup.py unpack -i MikroTik-plaintext.backup -d unpacked_backup`  

### Pack  
Pack all IDX and DAT files from a given directory in a plaintext backup    
`./ROSbackup.py pack -d unpacked_backup -o MikroTik-plaintext.backup` 

### Bruteforce
Bruteforce the password of an encrypted backup using a wordlist file  
`./ROSbackup.py bruteforce -i MikroTik-encrypted.backup -w wordlist.txt`  
If you have very large wordlist files, you can use parallel brute forcing  
`./ROSbackup.py bruteforce -i MikroTik-encrypted.backup -w wordlist.txt -p`  
On an Intel Xeon E3-1505M v6 @ 3.00GHz with 5 milion passwords:  
- Sequential: 45 seconds  
- Parallel: 12 seconds  
(The correct password was the latest)  

### Extract Users  
To extract Users and Password from .dat file  
`./extract_user.py unpacked_backup/user.dat`  

# Header structure
## Plaintext version
| Size (byte)  | Type | Name | Description |
| :----------: | ---- | ---- | ------- |
| 4 | Unsigned LE Int | Magic | 0xB1A1AC88 |
| 4 | Unsigned LE Int | File size | length in bytes |

## Encrypted version (RC4)
| Size (byte)  | Type | Name | Description |
| :----------: | ---- | ---- | ------- |
| 4 | Unsigned LE Int | Magic | 0x7291A8EF |
| 4 | Unsigned LE Int | File size | length in bytes |
| 32 | Byte array | Salt | Random salt added to password |
| 4 | Unsigned LE Int | Magic check | Encrypted Magic 0xB1A1AC88 to verify if password is correct |

## Encrypted version (AES128-CTR)  
RouterOS v6.43+ only  

| Size (byte)  | Type | Name | Description |
| :----------: | ---- | ---- | ------- |
| 4 | Unsigned LE Int | Magic | 0x7391A8EF |
| 4 | Unsigned LE Int | File size | length in bytes |
| 32 | Byte array | Salt | Random salt added to password |
| 32 | Byte array | Signature | SHA256 HMAC  |
| 4 | Unsigned LE Int | Magic check | Encrypted Magic 0xB1A1AC88 to verify if password is correct |

# Body structure
In the body are saved all file pair with extension .idx and .dat inside /flash/rw/store/  
For each file:  

| Size (byte)  | Type | Name | Description |
| :----------: | ---- | ---- | ------- |
| 4 | Unsigned LE Int | Filename length | Filename length without extension (.idx .dat) |
| Filename length | String | Filename | String without null byte terminator (and without extension .idx .dat)|
| 4 | Unsigned LE Int | IDX File size | length in bytes |
| IDX File size | Byte array | IDX File | content of IDX file |
| 4 | Unsigned LE Int | DAT File size | length in bytes |
| DAT File size | Byte array | DAT File | content of DAT file |

# IDX file structure
The index file contains infos about each entry of DAT file.    
For each entry:  

| Size (byte)  | Type | Name | Description |
| :----------: | ---- | ---- | ------- |
| 4 | Signed Int | Entry Index | The position of this entry in the Webfig/Winbox list, if -1 it means the entry was deleted and it won't be shown on Webfig/Winbox. |
| 4 | Signed Int | Entry Size | The size of this entry in bytes |
| 4 | Signed Int | Unused | It's always 5 (but in net/devices.idx it's 6 and in port_lock.idx it's -1) for each entry |

# Encryption setup
1) A random salt of 32 byte is generated (~~RouterOS only populates the first 16 bytes, mistake?~~) (Fixed)
2) The password is appended to the salt
3) salt+password result is hashed with SHA1 algorithm
4) RC4 cipher is initialized with the SHA1 hash
5) RC4 cipher skip first 0x300 (256 * 3 = 768) iterations
6) 0xB1A1AC88 is encrypted to check if password is correct before performing a decryption

# Comments
- When you delete some config (in Webfig or Winbox), they are not really deleted, they are only disabled and hidden, so if you unpack your backup, you can still recover them

# Dependences
- argparse
- pycrypto
