## where are the robots (100)

#### Description
> Can you find the robots? https://2019shell1.picoctf.com/problem/12267/ or http://2019shell1.picoctf.com:12267

#### Hint
> What part of the website could tell you where the creator doesn't want you to look?

#### Solution
Visit https://2019shell1.picoctf.com/problem/12267/robots.txt.
```
User-agent: *
Disallow: /713d3.html
```
Access that file, we got flag.
https://2019shell1.picoctf.com/problem/12267/713d3.html

#### Flag
`picoCTF{ca1cu1at1ng_Mach1n3s_713d3}`