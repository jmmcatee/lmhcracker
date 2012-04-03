## lmhcracker

lmhcracker is a tool to generate and brute force crack Windows LM Hashes. It uses the built in Go DES library for encryption.

## Installation

lmhcracker currently works with Go version 1.

	$ go build lmhcracker.go
	$ ./lmhcracker {flags} LMHash LMHash ...

## Running
To run lmhcracker you can just hand it a full LM Hash. You can set the number of routines (threads) used with the -p flag (default is max number of CPU cores).

## Example
The following command attempts to brute force LM Hashes (8 byte halves) for blank, ABCD, & 1234 using the maximum number of available cores.

	./lmhcracker e165f0192ef85ebbaad3b435b51404ee b757bf5c0d87772faad3b435b51404ee
