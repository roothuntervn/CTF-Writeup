# Newark Academy CTF 2019 Writeup
[CTFTime link](https://ctftime.org/event/869) | [Website](https://www.nactf.com/)

## Scoreboard

## Challenges

### [Cryptography](#cryptography-\--vyoms-soggy-croutons-50)
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

* * *

## [Cryptography] - Vyom's Soggy Croutons (50)

#### Description
> Vyom was eating a CAESAR salad with a bunch of wet croutons when he sent me this: ertkw{vk_kl_silkv}. Can you help me decipher his message?

#### Hint
> You don't have to decode it by hand -- Google is your friend!

#### Solution
Thanks to description, we know that the cipher is CAESAR. The shift key will be `ord('n') - ord('e') = 9`.
So, we can decrypt it using some online tools like [Cryptii](https://cryptii.com/) or writing python code:
```python
cipher = 'ertkw{vk_kl_silkv}'
key = ord('n') - ord('e')
plain = ''.join([chr((ord(c)-ord('a')+9)%26+ord('a')) if (ord(c)>=ord('a') and ord(c)<=ord('z')) else c for c in cipher])
print(plain)
```
#### Flag
`nactf{et_tu_brute}`

* * *

## [Cryptography] - Loony Tunes (50)

#### Description
> Ruthie is very inhumane. She keeps her precious pigs locked up in a pen. I heard that this secret message is the password to unlocking the gate to her PIGPEN. Unfortunately, Ruthie does not want people unlocking the gate so she encoded the password. Please help decrypt this code so that we can free the pigs! P.S. "\_" , "{" , and "}" are not part of the cipher and should not be changed. P.P.S the flag is all lowercase

#### File
![pig.jpg](Images/pig.jpg)

#### Solution
The description refers to pig many times, in order to refer to **Pigpen Cipher**
![pigpen cipher](Images/pigpen_cipher.png)

Using the cihper scheme, we can easily decrypt it

#### Flag
`nactf{th_th_th_thats_all_folks}`

* * *

## [Cryptography] - Reversible Sneaky Algorithm #0 (125)

#### Description
> Yavan sent me these really large numbers... what can they mean? He sent me the cipher "c", the private key "d", and the public modulus "n". I also know he converted his message to a number with ascii. For example:

> "nactf" --> \x6e61637466 --> 474080310374

> Can you help me decrypt his cipher?

#### Hint
> Read about RSA at https://en.wikipedia.org/wiki/RSA_(cryptosystem)

> If you're new to RSA, you may want to try this tool: https://www.dcode.fr/modular-exponentiation. If you like python, try the pow() function!

#### File
[rsa.txt](Files/rsa.txt)

#### Solution
This is a RSA chal. We have public key (n,c), and we also have private key (d). That's enough for decryption.

[RSA_0.py](Code/RSA_0.py)

#### Flag
`nactf{w3lc0me_t0_numb3r_th30ry}`

* * *

## [Cryptography] - Reversible Sneaky Algorithm #1 (275)

#### Description
> Lori decided to implement RSA without any security measures like random padding. Must be deterministic then, huh? Silly goose!

> She encrypted a message of the form nactf{****} where the redacted flag is a string of 4 lowercase alphabetical characters. Can you decrypt it?

> As in the previous problem, the message is converted to a number by converting ascii to hex.

#### Hint
> The flag seems pretty short... can you brute-force it?

> (Note: By brute-force, we do not mean brute-forcing the flag submission - do not SUBMIT dozens of flags. Brute force on your own computer.)

#### File
[ReversibleSneakyAlgorithm.txt](Files/ReversibleSneakyAlgorithm.txt)

#### Solution
Now we just have public key (n,e,c) and n is too big. We can't factorize n.
But the cipher space is small: `26^4 = 456976`. So we can brute force it.

[RSA_1.py](Code/RSA_1.py)

#### Flag
`nactf{pkcs}`

* * *

## [Cryptography] - Reversible Sneaky Algorithm #2 (350)

#### Description
> Oligar was thinking about number theory at AwesomeMath when he decided to encrypt a message with RSA. As a mathematician, he made various observations about the numbers. He told Molly one such observation:

> a^r ≡ 1 (mod n)

> He isn't SHOR if he accidentally revealed anything by telling Molly this fact... can you decrypt his message?

> Source code, a and r, public key, and ciphertext are attached.

#### Hint
> I'm pretty SHOR Oligar was building a quantum computer for something...

#### File
[shor.py](Files/shor.py)
[oligarchy.pem](Files/oligarchy.pem)
[are_you_shor.txt](Files/are_you_shor.txt)

#### Solution
From description and hint, we know that we need to use [SHOR algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm) to sovle the chal.
Based on the *algorithm*, we know that if 
```
f(x+r) = f(x) with f(x) = a^x mod (n)
```
then `r` divides `phi(n)`, where `phi(n)` denotes *Euler's totient function*.
If we choose x=0 then:
```
f(r) = a^r mod (n)
f(0) = a^0 mod (n) = 1 mod (n)
```
Because of `f(r) = f(0)`, so `r` divides `phi(n)`, or `phi(n) = k.r`. We just need to brute force `k`.
Once we know `phi(n)` and `n`, we can find out `p` and `q`. And that's enough. We can decrypt the cipher.

[RSA_2.py](Code/RSA_2.py)

#### Flag
`nactf{d0wn_wi7h_7h3_0lig4rchy}`

* * *

## [Cryptography] - Dr. J's Group Test Randomizer: Board Problem #0 (100)

#### Description
> Dr. J created a fast pseudorandom number generator (prng) to randomly assign pairs for the upcoming group test. Leaf really wants to know the pairs ahead of time... can you help him and predict the next output of Dr. J's prng? Leaf is pretty sure that Dr. J is using the middle-square method.

> nc shell.2019.nactf.com 31425

> The server is running the code in class-randomizer-0.c. Look at the function nextRand() to see how numbers are being generated!

#### Hint
> The middle-square method is completely determined by the previous random number... you can use a calculator and test that this is true!

#### File
[class-randomizer-0.c](Files/class-randomizer-0.c)

#### Chal
In the chal, Server gives us the current random number. We need to guess the 2 next random numbers.
```bash
$ nc shell.2019.nactf.com 31425

Welcome to Dr. J's Random Number Generator v1! 
[r] Print a new random number 
[g] Guess the next two random numbers and receive the flag! 
[q] Quit 

> r
311696200206400
> g

Guess the next two random numbers for a flag! You have a 0.0000000000000000000000000000001% chance of guessing both correctly... Good luck!
Enter your first guess:
> 3523452342345
That's incorrect. Get out of here!
```

#### Solution
Review the code, I found out that the nextRand() function will create new seed based on the previous one:
```c
uint64_t nextRand() {
  // Keep the 8 middle digits from 5 to 12 (inclusive) and square.
  seed = getDigits(seed, 5, 12);
  seed *= seed;
  return seed;
}
```
So, we can calculate the 2 next seeds easily.

[random_0.py](Code/random_0.py)

#### Flag
`nactf{1_l0v3_chunky_7urn1p5}`

* * *

## [Reverse Engineering] - Keygen (100)

#### Description
> Can you figure out what the key to this program is?

#### Hint
> Don't know where to start? Fire up a debugger, or look for cross-references to data you know something about.

#### File
[keygen-1](Files/keygen-1)

#### Solution
Using IDA to decompile the binary, we got [this](Code/keygen-1.c). 2 important functions:
```c
bool __cdecl sub_804928C(char *s)
{
  if ( strlen(s) != 15 )
    return 0;
  if ( s != strstr(s, "nactf{") )
    return 0;
  if ( s[14] == 125 )
    return sub_80491B6(s + 6) == 21380291284888LL;
  return 0;
}
```

So flag is **nactf{xxxxxxxx}**. We have to find out 8 characters in brackets. I will denotes it: **nactf{X}**.
```c
__int64 __cdecl sub_80491B6(_BYTE *a1)
{
  _BYTE *i; // [esp+4h] [ebp-Ch]
  __int64 v3; // [esp+8h] [ebp-8h]

  v3 = 0LL;
  for ( i = a1; i < a1 + 8; ++i )
  {
    v3 *= 62LL;
    if ( *i > 64 && *i <= 90 )
      v3 += (char)*i - 65;
    if ( *i > 96 && *i <= 122 )
      v3 += (char)*i - 71;
    if ( *i > 47 && *i <= 57 )
      v3 += (char)*i + 4;
  }
  return v3;
}
```

After doing some math stuffs, we finally got this:
```
v3 = 62^7 * x1 + 62^6 * x2 + ... + 62 * x7 + x8
with
	v3 = 21380291284888
	x[i] = X[i] - 65 if (X[i] > 64 && X[i] <= 90)
	x[i] = X[i] - 71 if X[i] > 96 && X[i] <= 122
	x[i] = X[i] + 4 if X[i] > 47 && X[i] <= 57
```

We can easily calculate **X** from v3.

[keygen.py](Code/keygen.py)

#### Flag
`nactf{xxxxxxxx}`


