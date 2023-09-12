---
title: "Watcher_1"
author: "Andrew Bernal"
type: ""
date: 2023-09-11T21:39:50-04:00
subtitle: ""
image: ""
tags: []
---
You can download the watcher from the /watcher_1.scr or /watcher_2.scr directories. 
The goal is to have a piece of harmless malware for people to run in the cyber security club meeting.

It is also my attempt to learn how processes can persist, and restart each other.
When the program runs, it adds itself to the registry to run on startup. Then it downloads its friend program. Then the two of them check to see if
notepad is open. If it is not open, they open it.


If watcher_1 detects watcher_2 is not running, it will restart watcher_2. 
I am working on a version where they send each other heartbeat messages through pipes.

