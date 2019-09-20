# Newark Academy CTF 2019 Writeup
[CTFTime link](https://ctftime.org/event/869) | [Website](https://www.nactf.com/)

## Scoreboard

## Challenges

### Cryptography
	- [x] Vyom's Soggy Croutons (50)
	- [x] Loony Tunes (50)
	- [x] Reversible Sneaky Algorithm #0 (125)
	- [x] Reversible Sneaky Algorithm #1 (275)
	- [x] Reversible Sneaky Algorithm #2 (350)
	- [x] Dr.J's Group Test Randomizer: Board Problem #0 (100)
	- [ ] Dr.J's Group Test Randomizer: Board Problem #1 (300)
	- [ ] Dr.J's Group Test Randomizer: Board Problem #2 (625)
	- [ ] Syper Duper AES (250)

### Reverse Engineering
	- [x] Keygen (600)

### General Skills
	- [x] Intro to Flags (10)
	- [x] Join the Discord (25)
	- [x] What the HEX? (25)
	- [x] Off-base (25)
	- [x] Cat over the wire (50)
	- [x] Grace's HashBrowns (50)
	- [x] Get a GREP #0! (100)
	- [x] Get a GREP #1! (125)
	- [x] SHCALC (200)
	- [x] Cellular Evolution #0: Bellsprout (75)
	- [x] Cellular Evolution #1: Weepinbell (125)
	- [x] Cellular Evolution #2: VikTreebel (150)
	- [ ] Cellular Evolution #3: BBOB (600)
	- [ ] Hwang's Hidden Handiwork (100)

### Binary Exploitation
	- [x] BufferOverflow #0 (100)
	- [x] BufferOverflow #1 (200)
	- [x] BufferOverflow #2 (200)
	- [x] Format #0 (200)
	- [x] Format #1 (250)
	- [ ] Loopy #0 (350)
	- [ ] Loopy #1 (500)

### Forensics
	- [x] Least Significant Avenger (50)
	- [x] The MetaMeme (75)
	- [x] Unzip Me (150)
	- [x] Kellen's Broken File (150)
	- [x] Kellen's PDF sandwich (150)
	- [x] Filesystem Image (200)
	- [x] Phuzzy Photo (250)
	- [x] File recovery (300)
	- [ ] My Ears Hurt (75)

### Web Exploitation
	- [x] Pink Panther (50)
	- [x] Scooby Doo (100)
	- [x] Dexter's Lab (125)
	- [x] Sesame Street (150)

## Cryptography

### Vyom's Soggy Croutons (50)

#### Description
> Vyom was eating a CAESAR salad with a bunch of wet croutons when he sent me this:
> ertkw{vk_kl_silkv}
> Can you help me decipher his message?
#### Hint
> You don't have to decode it by hand -- Google is your friend!
#### Solution
Thanks to description, we know that the cipher is CAESAR. The sift key will be `ord('n') - ord('e') = 9`. 
So, we can decrypt it using some online tool like [Cryptii](https://cryptii.com/) or writing some code:

	```
	print(''.join([chr((ord(c)-ord('a')+9)%26+ord('a')) if (ord(c)>=ord('a') and ord(c)<=ord('z')) else c for c in 'ertkw{vk_kl_silkv}']))
	```

*** nactf{et_tu_brute} ***
