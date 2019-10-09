## Open-to-admins (200)

#### Description
> This secure website allows users to access the flag only if they are **admin** and if the **time** is exactly 1400. https://2019shell1.picoctf.com/problem/37878/ (link) or http://2019shell1.picoctf.com:37878

#### Hint
> Can cookies help you to get the flag?

#### Solution
```bash
curl https://2019shell1.picoctf.com/problem/32205/flag -H "User-Agent:picobrowser"
```

#### Flag
`picoCTF{p1c0_s3cr3t_ag3nt_ee951878}`