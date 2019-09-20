# print(''.join([chr((ord(c)-ord('a')+9)%26+ord('a')) if (ord(c)>=ord('a') and ord(c)<=ord('z')) else c for c in 'ertkw{vk_kl_silkv}']))
cipher = 'ertkw{vk_kl_silkv}'
key = ord('n') - ord('e')
plain = ''.join([chr((ord(c)-ord('a')+9)%26+ord('a')) if (ord(c)>=ord('a') and ord(c)<=ord('z')) else c for c in cipher])
print(plain)