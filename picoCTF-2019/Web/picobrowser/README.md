## picobrowser (200)

#### Description
> This website can be rendered only by picobrowser, go and catch the flag! https://2019shell1.picoctf.com/problem/32205/ (link) or http://2019shell1.picoctf.com:32205

#### Hint
> You dont need to download a new web browser

#### Solution
```bash
curl https://2019shell1.picoctf.com/problem/32205/flag -H "User-Agent:picobrowser"
```

#### Flag
`picoCTF{p1c0_s3cr3t_ag3nt_ee951878}`