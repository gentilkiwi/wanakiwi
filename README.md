# Wanakiwi

## Introduction
This utility allows machines infected by the WannaCry ransomware to recover their files.

The original method is based on Adrien Guinet's [wannakey] (https://github.com/aguinet/wannakey) which consist of scanning the WannaCry process memory to recover the prime numbers that were not cleaned during CryptReleaseContext().

Adrien's method was originally described as only valid for Windows XP but we proven this can be extended to Windows 7.

**Wanakiwi** is based on the above method and **Wanadecrypt** which makes possible for lucky users to :
- Recover the private user key in memory to save it as `00000000.dky`
- Decrypt all of their files

![Alt text](/win7x86.png?raw=true "Optional Title")

## Limitations
Given the fact this method relies on scanning the address space of the process that generated those keys, this means that if this process had been killed by, for instance, a reboot - the original process memory will be lost. It is very important for users to *NOT* reboot their system before trying this tool.

Secondly, because of the same reason we do not know how long the prime numbers will be kept in the address space before being reused by the process. This is why it is important to try this utility ASAP.

This is not a perfect tool, but this has been so far the best solution for victims who had no backup.

## Compatibility

O.S.  | x86 | x64 |
------------- | ------------- | ------------- 
Windows XP  | :white_check_mark:  | ?
Windows 2003  | :white_check_mark:  | ?
Windows 7  | :white_check_mark:  | ? 

## Frequently Asked Questions
### Does it modify the original encrypted files ?
No, the original encrypted files (.WNCRY) remain unmodified. The decrypted files are generated as separate files.

## Resources
- https://blog.comae.io/wannacry-decrypting-files-with-wanakiwi-demo-86bafb81112d