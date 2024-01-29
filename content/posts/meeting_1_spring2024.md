---
title: "Meeting 1 Spring 2024"
author: "Andrew Bernal"
type: ""
date: 2024-01-29T17:48:46-05:00
subtitle: ""
image: ""
tags: []
---
# Meeting 1: BeEF
Welcome to the UML Cyber Security Club meeting 1. We have the great Felix

## Installation
1. `sudo apt install beef-xss`

2. `ip a` or `ifconfig` to get your ip address

3. `sudo beef-xss`

4. Web UI username is `beef`, the password is whatever you set

5. Send your friends a link to `http://<your IP>:3000/demos/butcher/index.html`

6. Stop the program with `sudo beef-xss-stop`
## Notes
- UML blocks Kali, so use a VPN when installing stuff to it
- Must be on the same network as your victim for the link to work (can use eduroam, or cyber range VPN network). 
- If you are using a VM, enable a "Bridged Adapter" instead of NAT
- In the GUI, `green` means likely to work, `orange` means may work, `red` means it probably won't work.

## Goals:
1. Get Noah's browser history
2. View IP address, browser, OS of victim
3. Get cookies of victim
4. Man-In-The-Browser
5. Confirm close Tab
6. DOS user
7. Use the Proxy to ping google or something
8. Use XSS Rays ??


## Extra Credit:
1. Integrate BeEF with Metasploit

## Use as Proxy
- Attacker can route their own internet traffic through the victim's browser
(Proxy Documentation)[https://github.com/beefproject/beef/wiki/Tunneling]

## XssRays
(XSS Rays Documentation)[https://github.com/beefproject/beef/wiki/Xss-Rays]
