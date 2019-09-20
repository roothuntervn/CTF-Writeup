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



## Cryptography - Vyom's Soggy Croutons (50)

#### Description
> Vyom was eating a CAESAR salad with a bunch of wet croutons when he sent me this: ertkw{vk_kl_silkv}. Can you help me decipher his message?

#### Hint
> You don't have to decode it by hand -- Google is your friend!

#### Solution
Thanks to description, we know that the cipher is CAESAR. The sift key will be `ord('n') - ord('e') = 9`. 
So, we can decrypt it using some online tool like [Cryptii](https://cryptii.com/) or writing some python code:
```python
cipher = 'ertkw{vk_kl_silkv}'
key = ord('n') - ord('e')
plain = ''.join([chr((ord(c)-ord('a')+9)%26+ord('a')) if (ord(c)>=ord('a') and ord(c)<=ord('z')) else c for c in cipher])
print(plain)
```
#### Flag
`nactf{et_tu_brute}`



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
```python
n = 140971369982728290584003929856637011308685429687969594429997821710108459830116393789723684079062708514036299475509430542212659734507429142853158004794834935174746493412962154796160975546005828130717579132438781804174244070129160649779404165370266408790722528108474736698480388956217393838955462967989235557729
d = 3210396717872682205420233842120187670754123682946955455494937957220148561826887372494355836977601850209792589944578254791223196877372140862540829182847721214418314564429696694983379689813325142035328881707722441498876726169675843996078221651180111278667814216844121752144791638682520989591783787929482763483
c = 7597447581111665937753781070914281099248138767561231457808924842755340796976767584904483452403406793827996034815852778012984740739361969304711271790657255334745163889379518040725967970769121270606356380463906882556650693485795903105298437519246733021136433493998710761239540681944709850299154477898517149127
m = pow(c, d, n)
print hex(m)[2:-1].decode('hex')
```
#### Flag
`nactf{w3lc0me_t0_numb3r_th30ry}`



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
```python
from itertools import product

n = 22211149480575639993429030519324903433947913532364781040868963328192510711356813047019777682976897694523708823502748768149007288902843985412808705624398873301639600888468250478096471710461804856036409585519537946352413960371213677893523940481424813184421465313214067723492301317054407961642320909213358344993453825109139928083868146685834149311590508677641684185974469669019522897333475910002506624356655715375691861599282035176111228787146595035293770294934083506588432931535561733381730924617763450268288785249430304809062568532772866407535937947253602671915278827388538023000320823892308918791287865032550658101647
e = 65537
c = 17092019895398435490936645877681389522100314381280314137324590582626113380519883878346612680436149571504342956062627199254592419000136198748264157134720216337534802137245374257104787163473593768075381161119603573787923015405105192411372689756878820005036480013443173993126005361536816259899310244534769833694660355126920566669139672444357708161337389888825104348833002955918763849005061351140425567156148202269336347554989169075541289307981444741551677799416273481457219933391047628725337828725080079301570909831609401028488393457876225318163558871115320155827798534306397644894097358075465535794590825299057956641732

alphabet = list('abcdefghijklmnopqrstuvwxyz')
L = list(product(alphabet, repeat = 4))

for s in L:
	flag = 'nactf{' + ''.join(s) + '}'
	message = int(flag.encode('hex'),16)
	cipher = pow(message, e, n)
	if cipher == c:
		print(flag)
		break
```

#### Flag
`nactf{pkcs}`



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
In the chal, Server give us the current random number. We need to guess the 2 next random numbers.
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
Review the code, I found out that the nextRand() function will create new seed based on previous one:
```c
uint64_t nextRand() {
  // Keep the 8 middle digits from 5 to 12 (inclusive) and square.
  seed = getDigits(seed, 5, 12);
  seed *= seed;
  return seed;
}
```

So, we can calculate the 2 next seeds using the code:
```python
from pwn import *

p = remote('shell.2019.nactf.com', 31425)
p.recvuntil('> ')
p.sendline('r')
num = p.recv().split('\n')[0].strip()
num_1 = long(str(num)[4:12]) ** 2
num_2 = long(str(num_1)[4:12]) ** 2
p.sendline('g')
p.recvuntil('> ')
p.sendline(str(num_1))
p.recv()
p.sendline(str(num_2))
p.interactive()
```
#### Flag
`nactf{1_l0v3_chunky_7urn1p5}`


