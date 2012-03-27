## lmhcracker

lmhcracker is a tool to generate and brute force crack Windows LM Hashes. It uses the built in Go DES library for encryption.

## Installation

lmhcracker currently works with Go release r60.

**Linux**

	$ gomake
	$ ./lmhcracker {flags} PARAMS

**Windows**

	$ C:\Go\bin\6g.exe lmhcracker.go
	$ C:\Go\bin\6l.exe -o .\lmhcracker.exe lmhcracker.6

## Running
To run lmhcracker you can just hand it a full LM Hash. You can set the number of routines (threads) used with the -p flag (default is 2).

## Example
The following command attempts to brute force LM Hashes (8 byte halves) for BLANK, ABCD, & 1234 using 4 guessing processes (Best to set -p to the number of cores or threads you have if that is more than two or leave it at the default, which is two).

	./lmhcracker -p 4 e165f0192ef85ebbaad3b435b51404ee b757bf5c0d87772faad3b435b51404ee
