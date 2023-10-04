---
title: "Meeting_4"
author: ""
type: ""
date: 2023-10-04T18:36:13-04:00
subtitle: ""
image: ""
tags: []
---
For better access to the files, go to the github: <https://github.com/UML-Cyber-Security/Fall_2023/blob/main/Meeting_4_Bad_Encryption/lab_4.md>
# Meeting 4
I encrypted my plan to take over the world. To stop me, you must decrypt my plan. The plan is stored in text files, for example [phase1.txt](phase1.txt). Each section links to its relevant phase.txt file.

# Table of Contents
- [1: Caesar Cipher](##1-caesar-cipher)
- [2: Substitution Cipher](##2-substitution-cipher)
- [3: Vigenère Cipher](##3-vigenère-cipher)
- [4: Playfair Cipher](##4-playfair-cipher)
- [5: RSA Cipher](##5-rsa-cipher)

## 1: Caesar Cipher
I suggest you use brute force to crack the [Encrypted file](phase1.txt)

The [Caesar Cipher](https://en.wikipedia.org/wiki/Caesar_cipher) is one of the most straightforward and oldest encryption techniques. Each letter in the plaintext is shifted a certain number of places down or up the alphabet. In the case of the Caesar cipher, there are only 26 possible shifts (considering the English alphabet). 

This means there are only 26 potential plaintexts to consider. For decryption, try each of the 26 possible shifts until you find the plaintext.

## 2: Substitution Cipher
[Encrypted file](phase2.txt). I suggest you use my example program `substitution_frequency.py`

Now we are not limited by the order of the alphabet. Any letter can map to any other letter. So instead of 26, there are 26! ways to map the letters to each other.

Why it is 26 factorial? A can be mapped to 26 possible choices. B can be mapped to 25 possible choices. etc. 

Substitution of my message into ascii, so it is random characters. I put it as hex so it is printable.

So [phase2.txt](phase2.txt) is in hex. You can put the hex into the program `substitution_frequency.py`.
My text is small, so it has a different frequency from english. To make it easier, I provided you the plot of my text's frequencies.

My frequencies:
![My frequencies](my_text_letter_frequencies.png)

English frequencies:
![Usual frequencies](absolute_letter_frequencies.png)

## 3: Vigenère Cipher
[Encrypted file](phase3.txt)

There are a few possible attacks.

## 4: Playfair Cipher
[Encrypted file](phase4.txt)

TThe text is not long enough to effectively do bigraph analysis. You would have to deduce the key square. I just made the key short instead.

The text starts with PHASEFOUR, and the key is of length 2.

I provided the `playfair.py` file for you to use in your programs.

http://www.jkhudson.plus.com/codes/playfair.htm

## 4: Playfair Cipher
[Encrypted file](phase4.txt)

Invented in 1854 by Charles Wheatstone, it was popularized and championed by Lord Playfair. Playfair is distinct from substitution ciphers because it encrypts digraphs, or pairs of letters, rather than individual letters. This approach gave it a significant edge over other ciphers, making it resistant to simple frequency analysis.

It was notably used by the British in the Boer War and World War I. Its elegance lies in its simplicity: a 5x5 grid (key square) made up of letters from the key, supplemented by the remaining letters of the alphabet (with 'I' and 'J' often combined to fit). Pairs of letters from the plaintext are then encrypted based on their position within this grid.

The ciphertext is too short for an effective bigram analysis. Instead, you can either try to deduce the key square, or brute force the key (it is 2 characters). 

[More information on playfair cipher](http://www.jkhudson.plus.com/codes/playfair.htm)

## 5: RSA
[Encrypted file](phase5.txt)