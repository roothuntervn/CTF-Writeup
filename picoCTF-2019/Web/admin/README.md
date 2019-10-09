## Open-to-admins (200)

#### Description
> This secure website allows users to access the flag only if they are **admin** and if the **time** is exactly 1400. https://2019shell1.picoctf.com/problem/37878/ (link) or http://2019shell1.picoctf.com:37878

#### Hint
> Can cookies help you to get the flag?

#### Solution
Edit cookie into this:
```
admin: True
time: 1400
```
Then visit the flag page.

#### Flag
`picoCTF{0p3n_t0_adm1n5_2e8d3883}`