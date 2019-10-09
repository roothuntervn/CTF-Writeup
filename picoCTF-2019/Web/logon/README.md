## logon (100)

#### Description
> The factory is hiding things from all of its users. Can you login as logon and find what they've been looking at? https://2019shell1.picoctf.com/problem/32270/ or http://2019shell1.picoctf.com:32270

#### Hint
> Hmm it doesn't seem to check anyone's password, except for {{name}}'s?

#### Solution
Login with arbitrary account, check the cookie we will see this:
```
username: foo
password: baz
admin: False
```
So, edit value of 'admin' into 'True', refresh the page, we got flag.

#### Flag
`picoCTF{th3_c0nsp1r4cy_l1v3s_a03e3590}`