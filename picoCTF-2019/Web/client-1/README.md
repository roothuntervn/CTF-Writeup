## dont-use-client-side (100)

#### Description
> Can you break into this super secure portal? https://2019shell1.picoctf.com/problem/32259/ or http://2019shell1.picoctf.com:32259

#### Hint
> Never trust the client

#### Solution
View-source, we got:
```javascript
function verify() {
checkpass = document.getElementById("pass").value;
split = 4;
if (checkpass.substring(0, split) == 'pico') {
  if (checkpass.substring(split*6, split*7) == 'b956') {
    if (checkpass.substring(split, split*2) == 'CTF{') {
     if (checkpass.substring(split*4, split*5) == 'ts_p') {
      if (checkpass.substring(split*3, split*4) == 'lien') {
        if (checkpass.substring(split*5, split*6) == 'lz_e') {
          if (checkpass.substring(split*2, split*3) == 'no_c') {
            if (checkpass.substring(split*7, split*8) == 'b}') {
              alert("Password Verified")
              }
            }
          }
  
        }
      }
    }
  }
}
else {
  alert("Incorrect password");
}

}
````

#### Flag
`picoCTF{no_clients_plz_eb956b}`