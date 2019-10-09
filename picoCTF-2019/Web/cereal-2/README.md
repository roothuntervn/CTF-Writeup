## cereal hacker 2 (500)

#### Description
> Get the admin's password. https://2019shell1.picoctf.com/problem/62195/ or http://2019shell1.picoctf.com:62195

#### Solution
**This is an unintended solution :)**

This time, we need to get the admin's password. However, we cannot login with `guest:guest`. We also cannot inject into cookie with this:
```
O:11:"permissions":1:{s:8:"username";s:10:"admin'-- -";}
```
But fortunately, we got a LFI, using **php wrapper** we can leak the source code:
```
https://2019shell1.picoctf.com/problem/62195/index.php?file=php://filter/convert.base64-encode/resource=index
```
Using this bug, we can get all the source code.

Now, you can see that the app uses *prepared statement*, so it's not injectable with SQLi. I cannot find a way to bypass it. So I use the bug of [cereal hacker 1](../cereal-1) to get flag of this chal LOL.

```
	if (!($prepared = $sql_conn_login->prepare("SELECT username, admin FROM pico_ch2.users WHERE username = ? AND password = ?;"))) {
	    die("SQL error");
	}
```
From this line, we know the `database` is `pico_ch2`, and the `table` is `users`.
So I will write some code to get flag of `cereal hacker 2` from `cereal hacker 1` using Blind SQL injection :)

You can review the code [here](exploit.py)

#### Flag
`picoCTF{c9f6ad462c6bb64a53c6e7a6452a6eb7}`
