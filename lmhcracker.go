package main

import (
	"bytes"
	"crypto/des"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"time"
)

var numParallelOp = flag.Int("p", runtime.NumCPU(), "Number of parallel processes to run")
var cpuprofile = flag.String("cpuprofile", "", "Write cpu profile to file")
var runBenchmark = flag.Bool("b", false, "Run program brenchmark")

var lmhashConstant = []byte("KGS!@#$%")
var posChars = []byte{0x00, /* NULL  */
	0x41 /* A */, 0x42 /* B */, 0x43 /* C */, 0x44 /* D */, 0x45, /* E */
	0x46 /* F */, 0x47 /* G */, 0x48 /* H */, 0x49 /* I */, 0x4A, /* J */
	0x4B /* K */, 0x4C /* L */, 0x4D /* M */, 0x4E /* N */, 0x4F, /* O */
	0x50 /* P */, 0x51 /* Q */, 0x52 /* R */, 0x53 /* S */, 0x54, /* T */
	0x55 /* U */, 0x56 /* V */, 0x57 /* W */, 0x58 /* X */, 0x59, /* Y */
	0x5A /* Z */, 0x30 /* 0 */, 0x31 /* 1 */, 0x32 /* 2 */, 0x33, /* 3 */
	0x34 /* 4 */, 0x35 /* 5 */, 0x36 /* 6 */, 0x37 /* 7 */, 0x38, /* 8 */
	0x39 /* 9 */, 0x21 /* ! */, 0x3F /* ? */, 0x2C /* , */, 0x2D, /* - */
	0x2E /* . */, 0x40 /* @ */, 0x20 /*   */, 0x22 /* " */, 0x23, /* # */
	0x24 /* $ */, 0x25 /* % */, 0x26 /* & */, 0x27 /* ' */, 0x28, /* ( */
	0x29 /* ) */, 0x2A /* * */, 0x2B /* + */, 0x2F /* / */, 0x3A, /* : */
	0x3B /* ; */, 0x3C /* < */, 0x3D /* = */, 0x3E /* > */, 0x5B, /* [ */
	0x5C /* \ */, 0x5D /* ] */, 0x5E /* ^ */, 0x5F /* _ */, 0x60, /* ` */
	0x7B /* { */, 0x7C /* | */, 0x7D /* } */, 0x7E /* ~ */}
var benchmarkInput = make([][]byte, 1)

type guessStatus struct {
	PosID            int
	Guesses          int64
	RunTime          float64
	FoundHash        bool
	Guess            []byte
	HashCrackedIndex int
}

type guessInfo struct {
	Position       int
	PosID          int
	GuessRange     []byte
	KnownHashes    [][]byte
	Ch             chan guessStatus
	CurrentSeed    []byte
	GuessStartTime time.Time
	Guesses        int64
}

func main() {
	// Start program timer
	progStartTime := time.Now()

	// Parse flag inputs
	flag.Parse()

	// Code used to profile program performance
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	// Set the number of threads using the input parameter given
	runtime.GOMAXPROCS(*numParallelOp + 1)

	var arraySize = 0
	if *runBenchmark {
		// ABCD
		benchmarkInput[0] = []byte{0xE1, 0x65, 0xF0, 0x19, 0x2E, 0xF8,
			0x5E, 0xBB, 0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE}
		// 1234
		benchmarkInput = append(benchmarkInput, []byte{0xB7, 0x57, 0xBF, 0x5C, 0x0D, 0x87,
			0x77, 0x2F, 0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE})
		// 9999
		benchmarkInput = append(benchmarkInput, []byte{0xA5, 0x93, 0x8F, 0x23, 0xD5, 0x47,
			0x19, 0xA0, 0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE})
		// AAAAA
		benchmarkInput = append(benchmarkInput, []byte{0xA8, 0x0F, 0x6E, 0x6A, 0x87, 0xBA,
			0x6A, 0xC2, 0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE})
		// EDCBA
		benchmarkInput = append(benchmarkInput, []byte{0x40, 0x97, 0xB2, 0x61, 0xB6, 0xA1,
			0x34, 0xCA, 0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE})
		// 1234F
		benchmarkInput = append(benchmarkInput, []byte{0x0E, 0xBB, 0x05, 0xDE, 0xE2, 0xD1,
			0xc0, 0xb9, 0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE})

		arraySize = len(benchmarkInput) * 2
	} else {
		arraySize = len(flag.Args()) * 2
	}

	unKnownLMHashes := make([][]byte, 2)
	crackedPassword := make([][]byte, arraySize)
	statusCh := make(chan guessStatus)

	fmt.Printf("Beginning LM Hash Brute Force Guessing... (%s)\n", progStartTime.String())
	fmt.Printf("- Looking for: \n")

	// Get input Hashes
	inputHashes := make([][]byte, arraySize)
	inputToCrackedMap := make([]int, arraySize)
	_ihCounter := 0

	if *runBenchmark {
		for _, value := range benchmarkInput {
			inputHashes[_ihCounter] = value[:8]
			_ihCounter++
			inputHashes[_ihCounter] = value[8:]
			_ihCounter++
		}
	} else {
		for _, value := range flag.Args() {
			input, _ := hex.DecodeString(value)
			inputHashes[_ihCounter] = input[:8]
			_ihCounter++
			inputHashes[_ihCounter] = input[8:]
			_ihCounter++
		}
	}

	// add to unknownLMHashes array
	var indexCounter = 0
	for i, input := range inputHashes {
		// check if has is already in
		check := false
		foundIndex := 0
		for j, unknown := range unKnownLMHashes {
			if bytes.Compare(input, unknown) == 0 {
				check = true
				foundIndex = j
			}
		}

		if !check {
			if i < 2 {
				unKnownLMHashes[i] = input
			} else {
				unKnownLMHashes = append(unKnownLMHashes, input)
			}

			inputToCrackedMap[i] = indexCounter
			indexCounter++
		} else {
			inputToCrackedMap[i] = foundIndex
		}
	}
	// Print hashes to find
	for _, value := range unKnownLMHashes {
		fmt.Printf("  - %X\n", value)
	}

	fmt.Printf("- Guessing Split into %d processes\n", *numParallelOp)

	guessSplit := divideWork()

	for i, value := range guessSplit {
		params := guessInfo{6,
			i,
			value,
			unKnownLMHashes,
			statusCh,
			[]byte{value[0], 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			time.Now(),
			0}
		go guessHashes(&params)
	}

	var foundKeys = 0
	for {
		stat := <-statusCh
		if stat.FoundHash {
			crackedPassword[stat.HashCrackedIndex] = stat.Guess
			foundKeys++
		} else {
			if stat.RunTime != 0 {
				fmt.Printf("- Process %d: Guesses:%d (%f/s) Last Guess:%X\n", stat.PosID,
					stat.Guesses, float64(stat.Guesses)/stat.RunTime, stat.Guess)
			}
		}

		if foundKeys == len(unKnownLMHashes) {
			break
		}
	}

	time.Sleep(10)
	fmt.Printf("\n\nFound Keys (Took %s seconds)\n", time.Now().Sub(progStartTime))

	// Print hashes in correct order with inputToCrackedMap
	for i, _ := range inputHashes {
		if i%2 == 1 && i != 0 {
			fmt.Printf("- Given: %X%X \n", inputHashes[i-1], inputHashes[i])
			_first := crackedPassword[inputToCrackedMap[i-1]]
			_second := crackedPassword[inputToCrackedMap[i]]
			fmt.Printf("  Cracked: %X%X (%s%s)\n", _first, _second, _first, _second)
		}
	}

}

func divideWork() [][]byte {
	guessSplit := make([][]byte, *numParallelOp)
	j := 0
	for _, value := range posChars {
		guessSplit[j] = append(guessSplit[j], value)
		if j == (*numParallelOp - 1) {
			j = 0
		} else {
			j++
		}
	}
	return guessSplit
}

func guessHashes(params *guessInfo) (paramsOut *guessInfo) {
	for _, currentChar := range posChars {
		params.CurrentSeed[params.Position] = currentChar
		if params.Position > 0 {
			params.Position = params.Position - 1
			params = guessHashes(params)
		}
		if params.Position == 4 {
			params.Ch <- guessStatus{params.PosID,
				params.Guesses,
				time.Now().Sub(params.GuessStartTime).Seconds(),
				false,
				params.CurrentSeed,
				0}
		}

		if params.Position == 0 {
			for _, currentGuess := range params.GuessRange {
				params.CurrentSeed[params.Position] = currentGuess
				var guessHash = createLMHash(params.CurrentSeed)
				for i, currentCheckHash := range params.KnownHashes {
					if bytes.Compare(guessHash, currentCheckHash) == 0 {
						// The []byte call keeps the data in the channel from being
						// changed once it is mapped on the other side. By 
						// creating a seperate array a new untouched space is used.
						params.Ch <- guessStatus{params.PosID,
							params.Guesses,
							time.Now().Sub(params.GuessStartTime).Seconds(),
							true,
							[]byte{params.CurrentSeed[0],
								params.CurrentSeed[1],
								params.CurrentSeed[2],
								params.CurrentSeed[3],
								params.CurrentSeed[4],
								params.CurrentSeed[5],
								params.CurrentSeed[6],
								0x00},
							i}
						fmt.Printf("::FOUND KEY: %s (%X) at (%s seconds) process:%d\n",
							params.CurrentSeed, params.CurrentSeed,
							time.Now().Sub(params.GuessStartTime), params.PosID)
					}
				}
				params.Guesses++
			}
			/* Because the 0 index has split guess characters for parallel work break once loop 
			is done to allow the 1 index to increment to the next full posChars character.
			*/
			break
		}
	}
	params.Position++
	return params
}

func createLMHash(passHalve []byte) (hashHalve []byte) {
	// Create 0'd key and hash slices and set the constant input
	// used to the password halve key against.
	key := make([]byte, 8)
	hash := make([]byte, 8)

	// Do bit flipping to turn password halve into a DES key
	key[0] = (passHalve[0] >> 1) << 1
	key[1] = (((passHalve[0] & 0x01) << 6) | (passHalve[1] >> 2)) << 1
	key[2] = (((passHalve[1] & 0x03) << 5) | (passHalve[2] >> 3)) << 1
	key[3] = (((passHalve[2] & 0x07) << 4) | (passHalve[3] >> 4)) << 1
	key[4] = (((passHalve[3] & 0x0F) << 3) | (passHalve[4] >> 5)) << 1
	key[5] = (((passHalve[4] & 0x1F) << 2) | (passHalve[5] >> 6)) << 1
	key[6] = (((passHalve[5] & 0x3F) << 1) | (passHalve[6] >> 7)) << 1
	key[7] = (passHalve[6] & 0x7F) << 1

	// Create a new DES cipher and then encrypt the LM constant
	// with the DES key made from the password halve provided
	desCipher, _ := des.NewCipher(key)
	desCipher.Encrypt(hash, lmhashConstant)

	// return the output hash value
	return hash
}
