package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"golang.org/x/crypto/ripemd160"
	"log"
	"math/bits"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	SALT       = ""
	DIFFICULTY = 0
	CHECKSUM   = 0x0
	PREFIX     = ""
)

const (
	VERSION = "2018-03-04a"
	MAXDIFC = 31
)

func hex256(dwords []int32, separator string) string {
	if len(dwords) != 8 {
		log.Fatal("hex256: bad dwords")
	}
	var res []string
	for i := 0; i < 8; i++ {
		res = append(res, fmt.Sprintf("%x", uint32(dwords[i])))
	}
	return strings.Join(res, separator)
}

func sha256dwords(input string) []int32 {
	h := sha256hex(input)
	decoded, _ := hex.DecodeString(h)
	var out []int32
	var ret [8]int32
	buf := bytes.NewBuffer(decoded)
	binary.Read(buf, binary.BigEndian, &ret)

	for _, dword := range ret {
		out = append(out, int32(dword))
	}
	return out
}

func sha256hex(input string) string {
	h := sha256.New()
	for i, _ := range input {
		dec, _ := utf8.DecodeRuneInString(input[i:])
		binary.Write(h, binary.LittleEndian, int8(dec))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func ripemd160hex(input string) string {
	h := ripemd160.New()
	h.Write([]byte(input))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func assert(a interface{}, b interface{}, msg string) {
	if a != b {
		fmt.Printf("%s != %s [%s]\n", a, b, msg)
		os.Exit(1)
	}
}

func lrshift(n int32, shft uint32) int32 {
	return (n >> shft) & (0x7fffffff >> (shft - 1))
}

func rol(x int32, k int) int32 {
	const n = 32
	s := uint(k) & (n - 1)
	return x<<s | x>>(n-s)
}

var pubkeyCache map[string]string

func privkeyToPubkey(secret0 string) string {
	if len(secret0) <= 30 {
		log.Fatal("privkeyToPubkey: secret0 bad len")
	}
	if val, ok := pubkeyCache[secret0]; ok {
		fmt.Println("Retrived cached BTC pubkey.")
		return val
	}
	/*newb := func(f int64) *big.Float { return new(big.Float).SetInt(big.NewInt(f)) }
	  parb := func(s string) *big.Float {
	    fn := new(big.Float)
	    fp, _, _ := fn.Parse(s, 2)
	    return fp.Set(fp)
	  }
	  one := newb(1)
	  two := newb(2)
	  three := newb(3)
	  p := parb("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	  gx := parb("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	  gy := parb("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
	  order := parb("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	  secret := parb(secret0)

	  inverseMod := func(a *big.Float) {
	    if a.Cmp(p) < 1 {
	      a = a.Mod(p)
	    }
	  }

	  fmt.Printf("one = %v, two = %v, three = %v, p = %p\n", one, two, three, p)
	  return ""*/
	return ""
}

func binToAnyModule() func() {
	// TODO implement
	return func() {}
}

func dwordsToChars(ns []int32) string {
	var out []string
	for _, dword := range ns {
		for i := 0; i < 4; i++ {
			dword = int32(bits.RotateLeft32(uint32(dword), 8))
			out = append(out, string(0xff&dword))
		}
	}
	return strings.Join(out, "")
}

func charsToDwords(str string) []int32 {
	for len(str) == 0 || len(str)%4 != 0 {
		str = string(0) + str
	}
	var result []int32
	for idwrd := 0; idwrd < len(str); idwrd = idwrd + 4 {
		var dword int32 = 0
		for j := 0; j <= 3; j++ {
			dword = rol(dword, 8) | int32(str[idwrd+j])
		}
		result = append(result, dword)
	}
	return result
}

func dwordsToPassword(dwords []int32, fives int) string {
	chars := "$*23456789abcdef@hijk(mnop)rstuvwxyzABCDEFGH=JKLMN#PQRSTUVWXYZ!?"
	if len(dwords) != 8 {
		log.Fatal("bip39: wrong dwords")
	}
	var result []string
	for i := 0; i < fives; i++ {
		dword := dwords[i]
		for j := 0; j < 5; j++ {
			dword = int32(bits.RotateLeft32(uint32(dword), 6))
			num := (dword & 63)
			result = append(result, chars[num:num+1])
		}
	}
	return strings.Join(result, "")
}

func get256bits(rand func() int32) []int32 {
	var dwords []int32
	for i := 0; i < 8; i++ {
		var dword int32 = 0
		for j := 0; j < 32; j++ {
			got := int32(rand())
			bitsel := got & 0xf
			dword = rol(dword, 1)
			dword = dword | (1 & rol(got, int(-(bitsel+8))))
		}
		dwords = append(dwords, dword)
	}
	return dwords
}

func toBase58(string) {
	// TODO implement
}

func toBin(dwords []int32) []int32 {
	var res []int32
	for _, dword := range dwords {
		for i := 0; i < 32; i++ {
			dword = rol(dword, 1)
			res = append(res, dword&1)
		}
	}
	return res
}

func toBinstr(n int32) string {
	bin := toBin([]int32{n})
	return strings.Trim(strings.Join(strings.Fields(fmt.Sprint(bin)), ""), "[]")
}

func bitstream(rem_bits []int32) func(take int) int32 {
	return func(take int) int32 {
		if take > 32 {
			log.Fatal("bitstream: bad take size")
		}
		var result int32 = 0
		for i := int(0); i < take; i++ {
			result = rol(result, 1)
			result = result | int32(rem_bits[0])
			rem_bits = append(rem_bits[:0], rem_bits[1:]...)
		}
		return result
	}
}

func newShifter(state int64) (func() bool, func() int64) {
	if state == 0 {
		state = 1
	}
	return func() bool {
			bt := state & 1
			state = int64(lrshift(int32(state), 1))
			if bt == 1 {
				state = state ^ 0xa3000000
				return true
			}
			return false
		}, func() int64 {
			return state
		}
}

func newRandom(dwords []int32) (func() int32, func() []int32) {
	w, x, y, z := dwords[0], dwords[1], dwords[2], dwords[3]
	sh1, sh1d := newShifter(int64(dwords[4]))
	sh2, sh2d := newShifter(int64(dwords[5]))
	sh3, sh3d := newShifter(int64(dwords[6]))
	sh4, sh4d := newShifter(int64(dwords[7]))

	if (w | x | y | z) == 0 {
		w, x, y, z = 0, 0, 0, 1
	}
	fun := func() int32 {
		for {
			var t int32 = x ^ (x << uint(11))
			x, y, z = y, z, w
			w = w ^ lrshift(w, 19) ^ t ^ lrshift(t, 8)
			if sh1() || sh2() || sh3() || sh4() {
				break
			}
		}
		return w
	}
	dump := func() []int32 {
		return []int32{int32(w), int32(x), int32(y), int32(z), int32(sh1d()), int32(sh2d()), int32(sh3d()), int32(sh4d())}
	}
	for i := 0; i < 10; i++ {
		fun()
	}
	return fun, dump
}

func bip39(dwords []int32) string {
	if !(len(dwords) >= 1 && len(dwords) <= 8) {
		log.Fatal("bip39: bad dwords input")
	}
	result := toBin(dwords)
	for i := 0; i < len(dwords); i++ {
		// TODO repair !!!! cs must be bool
		//cs := chksum(1)
		result = append(result, 1)
	}

	if len(result) != len(dwords)*33 {
		log.Fatal("bip39: bad dwords recalculate")
	}
	var resultstr []string
	bs := bitstream(result)
	for i := 0; i < len(dwords)*3; i++ {
		resultstr = append(resultstr, WORDLIST[bs(11)])
	}
	return strings.Join(resultstr, " ")
}

func keymaster(seedstring string, difc int, progress bool) ([]int32, time.Duration) {
	iterations := 0x100000
	one64 := lrshift(int32(iterations), 6)
	lsha := sha256dwords(seedstring)

	// TODO - implement progress
	rnd, _ := newRandom(lsha)
	difmask := lrshift(-1, uint32(32-difc))
	t0 := time.Now()
	for round := 0; round < 64; round++ {
		for i := 0; i < int(one64); i++ {
			difmask = int32(bits.RotateLeft32(uint32(difmask), -int(rnd()&31)))
			seek := difmask & rnd()
			for {
				got := difmask & rnd()
				if got == seek {
					break
				}
			}
		}
	}
	master := get256bits(rnd)
	return master, time.Since(t0)
}

func calibrate() bool {
	for difc := 1; difc <= MAXDIFC; difc++ {
		fmt.Printf("Trying difficulty %d \n", difc)
		_, time := keymaster("Xuul", difc, true)
		ntime := float64(time.Seconds())
		fmt.Printf("Seconds: %.2f seconds.\n\n", ntime)
		if ntime >= 10 {
			fmt.Println("\nCALIBRATION RESULTS FOR THIS MACHINE:")
			for d := difc; d <= MAXDIFC; d++ {
				t := ntime
				ts := fmt.Sprintf("%.2f seconds", ntime)
				if t > 180 {
					t = t / 60
					ts = fmt.Sprintf("%.2f minutes", t)
					if t > 180 {
						t = t / 60
						ts = fmt.Sprintf("%.2f hours", t)
						if t > 72 {
							t = t / 24
							ts = fmt.Sprintf("%.2f days", t)
							if t > 1000 {
								t = t / 365
								ts = fmt.Sprintf("%.2f years", t)
							}
						}
					}
				}
				fmt.Printf("Difficulty %d takes approx. %s\n", d, ts)
				ntime = ntime * 2
			}
			return true
		}
	}
	return true
}

func btcPrivkey() {
	// TODO
}

func wif() {
	// TODO
}

func checkwords(str string, howmany int) string {
	if howmany < 1 || howmany > 8 {
		log.Fatal("checkwords: bad howmany")
	}
	ichksum := sha256dwords(str + "\000checkwords")
	var result []string
	for i := 0; i < howmany; i++ {
		result = append(result, WORDLIST[ichksum[i]&0x7ff])
	}
	return strings.Join(result, " ")
}

type prefixes map[string]bool

func getAllPrefixes() prefixes {
	def := []string{"hex", "btcc", "btcu", "pwd15", "pwd40", "wrd12", "wrd24"}
	p := make(prefixes)
	for _, prefix := range def {
		p[prefix] = true
	}
	return p
}

func test() {
	fmt.Printf("Running self-tests.\n")

	assert(toBinstr(7), "00000000000000000000000000000111", "")

	bs := bitstream([]int32{1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0})
	assert(bs(4), int32(14), "")
	assert(bs(4), int32(3), "")
	assert(dwordsToChars([]int32{0x41424344, 0x31323334}), "ABCD1234", "")

	res := charsToDwords("12ABCD")
	assert(res[0], int32(0x00003132), "")
	assert(res[1], int32(0x41424344), "")

	assert(ripemd160hex(""), "9c1185a5c5e9fc54612808977ee8f548b2258d31", "")
	assert(ripemd160hex("The quick brown fox jumps over the lazy dog"), "37f332f68db77bd9d7edd4969571ad671cf9dd3b", "")
	assert(sha256hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "")
	assert(sha256hex("The quick brown fox jumps over the lazy dog"), "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", "")

	// TODO - QR.test()

	sh, shDump := newShifter(0x12345678)
	for i := 0; i < 100; i++ {
		sh()
	}
	assert(int64(shDump()), int64(0x8d8aa8c3), "")

	dwords := []int32{1, 0}
	assert(bip39(dwords), "abandon abandon able abandon abandon about", "")

	rnd0, rnd0dump := newRandom([]int32{0, 0, 0, 1, 1, 1, 1, 1})
	for i := 0; i < 990; i++ {
		rnd0()
	}
	dump := rnd0dump()
	for i, val := range []int32{-425834366, -1723937955, -1169188817, 196064729, 1187056870, 54142212, 505423191, -346763885} {
		assert(val, dump[i], fmt.Sprintf("bad %d", i))
	}
	assert(rnd0(), int32(-1986718929), "")
	key := get256bits(rnd0)
	assert(hex256(key, "-"), "e7ba2240-c5aa7fe7-584a794e-c0ab7d4b-1b74cf7b-ccbaf55d-b5e5b889-1442c646", "")
	assert(dwordsToPassword(key, 8), "VXEy@N)F?Vm4FVjMaJZi6TjfuPbHRnJumUy54b6h", "")

	testkey, _ := keymaster("Satan", 2, false)
	assert(hex256(testkey, "-"), "16784c4f-eb122684-376d1d73-375adccd-133b10cf-4ef0bac3-abe34427-a09aecd2", "")
	// TODO implement test
	//assert(binToAny((dwordsToChars({0x12345678,0xffffffff}),"0123456789abcdef") == "12345678ffffffff"), "")
	//assert(toBase58({0x80, 0x32247122, 0xF9FF8BB7, 0x8BBEFC55, 0x4E729121, 0x24410788, 0x2417AF0D, 0x77EB7A22, 0x784171F2, 0xAB079763}), "5JCNQBno4UP562LCEXMTr72WVUe31     5rrXzPqAFiap8zQNjzarbL", "")

	assert(checkwords("Homopes", 2), "devote asthma", "")

	// TODO BTC pubkey generation test

	fmt.Println("All self-tests OK")
}

type options struct {
	salt        string
	difficulty  int
	checksum    int
	prefix      string
	no_btc_addr bool
	calibrate   bool
	test        bool
}

func main() {
	fmt.Printf("gokrypta %s\n", VERSION)

	opts := options{}

	flag.BoolVar(&opts.test, "test", false,
		"Do all self tests, print a test QR code (of random BTC private key) and quit")

	flag.BoolVar(&opts.calibrate, "calibrate", false,
		"Runs a calibration that shows you how much time (approximately) it takes\n"+
			"o generate the master key for various difficulties.")

	flag.StringVar(&opts.salt, "salt", SALT,
		"Specify salt which is combined with your passphrase to generate master key.\n"+
			"Note that having passphrase \"abc\" and salt \"def\" is not the same thing\n"+
			"as having passphrase \"abcdef\" (or \"defabc\") without salt.")

	flag.IntVar(&opts.difficulty, "difficulty", DIFFICULTY,
		"Select the difficulty for master key generation (1 to 31).\n"+
			"Each subsequent difficulty is twice slower than the previous.\n"+
			"1 is fastest. 31 takes many years. Use the \"calibrate\" option\n"+
			"to find the best difficulty.")

	flag.IntVar(&opts.checksum, "checksum", CHECKSUM,
		"Specify checksum for your master passphrase (0x and three hex digits).\n"+
			"Useful to be sure that you entered the passphrase correctly.\n"+
			"Using it degrades you security a tiny little bit because if the attacker\n"+
			"knows it, he can easily check if his master passphrase and difficulty guess\n"+
			"is correct or not.")

	flag.StringVar(&opts.prefix, "prefix", PREFIX,
		"Automatically sets default prefix. Entering \"xyz\" as an index then\n"+
			"automatically selects index \"pwd12:xyz\". Use index \"all:xyz\" to show\n"+
			"all prefixes (the same result as entering index \"xyz\" when no default\n"+
			"prefix is set).")

	flag.BoolVar(&opts.no_btc_addr, "no_btc_addr", false,
		"Disables generating BTC addresses (and saves a few seconds of time).\n"+
			"Note that BTC private keys generation is still enabled because it's fast.\n"+
			"The BTC address generation algorithm is currently very naive and rather slow.\n"+
			"It can be significantly improved.")

	flag.Parse()

	if opts.test {
		test()
		os.Exit(0)
	}

	if opts.calibrate {
		fmt.Println("Calibrating the difficulty...")
		calibrate()
		os.Exit(0)
	}

	fmt.Printf("STARTING!\n")
	test()

	fmt.Printf("SALT='%s' (%d characters)\n", opts.salt, len(opts.salt))
	if len(opts.salt) == 0 {
		fmt.Println("WARNING! 'SALT' is not set. Set it to be more secure.")
	}

	if opts.checksum == 0 {
		fmt.Println("Checksum not set, will display it.")
	}

	fmt.Printf("Please enter your super-secret MASTER PASSPHRASE:\n")
	var masterpp string
	_, err := fmt.Scan(&masterpp)
	if err != nil {
		log.Println(err)
	}
	for i := 0; i < 200; i++ {
		fmt.Println("")
	}
	if len(masterpp) < 10 {
		fmt.Println("WARNING: Master passphrase is very short.")
	}

	zeroes := dwordsToChars([]int32{0})
	masterseed := masterpp + zeroes + opts.salt
	fmt.Printf("Calculating master key at difficulty %d\n", opts.difficulty)
	masterkey, time := keymaster(masterseed, opts.difficulty, true)
	fmt.Printf("Masterkey generated in %.2f seconds.\n", float64(time.Seconds()))
	chsum := 0xfff & (masterkey[0] ^ masterkey[6] ^ masterkey[7])
	fmt.Printf("Masterkey checksum is: 0x%03x\n", chsum)

	if opts.checksum != 0 {
		if int32(opts.checksum) != chsum {
			log.Fatal("!!! CHECKSUM DOES NOT MATCH !!!")
		} else {
			fmt.Println("Checksum matches.")
		}
	}
	strseed0 := dwordsToChars(masterkey)

	for true {
		fmt.Println("\n----------------------------------")
		if opts.prefix != "" {
			fmt.Printf("Default prefix is '%s:' (override with 'all:')\n", opts.prefix)
		}
		fmt.Println("Enter index with optional 'prefix:' (default='')")
		var ind0 string
		_, err := fmt.Scan(&ind0)
		if err != nil {
			log.Println(err)
		}

		var prefix, index string
		re, _ := regexp.Compile("^(.+):(.*)$")
		if re.MatchString(ind0) {
			reo := re.FindStringSubmatch(ind0)
			prefix = reo[1]
			index = reo[2]
			fmt.Printf("reo=%v\n", reo)
		}
		if opts.prefix != "" {
			prefix = opts.prefix
			index = ind0
		}
		if prefix == "all" {
			prefix = ""
			ind0 = index
		}
		show := getAllPrefixes()

		if index != "" && prefix != "" {
			if !show[prefix] {
				fmt.Printf("Error: Prefix '%s' is invalid.", prefix)
				show = make(prefixes)
			} else {
				show[prefix] = true
			}
		} else {
			index = ind0
		}
		match, _ := regexp.MatchString(":", index)
		if match {
			fmt.Println("Error: Colon (':') detected but no valid prefix and index.")
			show = make(prefixes)
		}
		if len(show) > 0 {
			fmt.Printf("Entered index string: '%s' (%d chars)\n", index, len(index))
			rnd, _ := newRandom(sha256dwords(index + zeroes + strseed0))
			result := get256bits(rnd)

			if len(result) != 8 {
				log.Fatal("result is not 8 len")
			}
			if prefix != "" {
				fmt.Printf("Checkwords for this specific master passphrase, prefix and index (%s:%s): '%s'\n",
					prefix, index, checkwords(strseed0+dwordsToChars(result)+prefix, 3))
			} else {
				fmt.Printf("Checkwords for this specific master passphrase and index (no prefix): '%s'\n", checkwords(strseed0+dwordsToChars(result), 2))
			}

			if show["hex"] {
				fmt.Printf("(hex:) 256bit hex number: %s\n", hex256(result, ""))
				fmt.Printf("(hex:) With spaces: %s\n", hex256(result, " "))
			}
			/*var pubkey string
			if !opts.no_btc_addr && (show["btcc"] || show["btcu"]) {
				pubkey = privkeyToPubkey("0x" + hex256(result, ""))
			}*/
			//privkeys = btc_privkey(result)
			//fmt.Println(pubkey)
		}
	}
}

var WORDLIST []string = []string{"abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become", "beef", "before", "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry", "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog", "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child", "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle", "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog", "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut", "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come", "comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress", "connect", "consider", "control", "convince", "cook", "cool", "copper", "copy", "coral", "core", "corn", "correct", "cost", "cotton", "couch", "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle", "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream", "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard", "curious", "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad", "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december", "decide", "decline", "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay", "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend", "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk", "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display", "distance", "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft", "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip", "drive", "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo", "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either", "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else", "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable", "enact", "end", "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode", "equal", "equip", "era", "erase", "erode", "erosion", "error", "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil", "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend", "extra", "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame", "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female", "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure", "file", "film", "filter", "final", "find", "fine", "finger", "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash", "flat", "flavor", "flee", "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly", "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot", "force", "forest", "forget", "fork", "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile", "frame", "frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown", "frozen", "fruit", "fuel", "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy", "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp", "gate", "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance", "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue", "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green", "grid", "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy", "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health", "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen", "hero", "hidden", "high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow", "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host", "hotel", "hour", "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify", "idle", "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune", "impact", "impose", "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate", "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial", "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane", "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest", "invite", "involve", "iron", "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge", "juice", "jump", "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know", "lab", "label", "labor", "ladder", "lady", "lake", "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law", "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture", "left", "leg", "legal", "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty", "library", "license", "life", "lift", "light", "like", "limb", "limit", "link", "lion", "liquid", "list", "little", "live", "lizard", "load", "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop", "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet", "maid", "mail", "main", "major", "make", "mammal", "man", "manage", "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine", "market", "marriage", "mask", "mass", "master", "match", "material", "math", "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media", "melody", "melt", "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry", "mesh", "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind", "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed", "mixture", "mobile", "model", "modify", "mom", "moment", "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning", "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie", "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music", "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin", "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative", "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral", "never", "news", "next", "nice", "night", "noble", "noise", "nominee", "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice", "novel", "now", "nuclear", "number", "nurse", "nut", "oak", "obey", "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean", "october", "odor", "off", "offer", "office", "often", "oil", "okay", "old", "olive", "olympic", "omit", "once", "one", "onion", "online", "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit", "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich", "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over", "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper", "parade", "parent", "park", "parrot", "party", "pass", "patch", "path", "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper", "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical", "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play", "please", "pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar", "pole", "police", "pond", "pony", "pool", "popular", "portion", "position", "possible", "post", "potato", "pottery", "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare", "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority", "prison", "private", "prize", "problem", "process", "produce", "profit", "program", "project", "promote", "proof", "property", "prosper", "protect", "proud", "provide", "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle", "pyramid", "quality", "quantum", "quarter", "question", "quick", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail", "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid", "rare", "rate", "rather", "raven", "raw", "razor", "ready", "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle", "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject", "relax", "release", "relief", "rely", "remain", "remember", "remind", "remove", "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report", "require", "rescue", "resemble", "resist", "resource", "response", "result", "retire", "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib", "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket", "romance", "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say", "scale", "scan", "scare", "scatter", "scene", "scheme", "school", "science", "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea", "search", "season", "seat", "second", "secret", "section", "security", "seed", "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence", "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft", "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine", "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side", "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar", "simple", "since", "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch", "ski", "skill", "skin", "skirt", "skull", "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan", "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup", "source", "south", "space", "spare", "spatial", "spawn", "speak", "special", "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay", "steak", "steel", "stem", "step", "stereo", "stick", "still", "sting", "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street", "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject", "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun", "sunny", "sunset", "super", "supply", "supreme", "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain", "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup", "system", "table", "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target", "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten", "tenant", "tennis", "tent", "term", "test", "text", "thank", "that", "theme", "then", "theory", "there", "they", "thing", "this", "thought", "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger", "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco", "today", "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top", "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist", "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic", "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree", "trend", "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck", "true", "truly", "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle", "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical", "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo", "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown", "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge", "usage", "use", "used", "useful", "useless", "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley", "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle", "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel", "veteran", "viable", "vibrant", "vicious", "victory", "video", "view", "village", "vintage", "violin", "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal", "voice", "void", "volcano", "volume", "vote", "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut", "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave", "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend", "weird", "welcome", "west", "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip", "whisper", "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing", "wink", "winner", "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder", "wood", "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year", "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo"}
