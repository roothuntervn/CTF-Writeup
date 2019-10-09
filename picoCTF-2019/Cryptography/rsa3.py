from gmpy2 import *
from functools import reduce

n = 13621157870572609021079315102489688689594886758930788373338838409533251469312729727598581650137969964446069777072542946640095893365037008193416166419891881092722923933122057007129368517114653121693199681129431015880318796871058968554620713875561093892699783339893256594994434832032365061518885985759862860514341078515119479137697499011170298291
c = 5996462035960426432770699074292314294808686679449888009305549092134777723757496441465417629678035056538116086497915418955390868666735256823449023101803655998635177996043230575473922219332501212325362423434053495784828847303631266776729979371864528012390395556327924881917217808362783653198933191447728535674518527210439433305012370811355287089
e = 65537

p = 2523295477314271572736185001581976057577860410383514518383643
q = 33464678461496844885643710203176372566306925690179500330035440172340429
r = 883585500461467616836302066333305403416736551383378171693824136399815661318488913
s = 182562124116551458496871370389043050994122320825527059406755444727580340601557312128104029848095934997009461802823611691819514937181

_P = [9179468237, 10416167633, 12099975817, 12455660101, 13205291447, 13259995717]
_Q = [8680195169, 9593649089, 11218022801, 11632752353, 13446979453, 13712127809, 16701094849]
_R = [9212263519, 10222655977, 10696245863, 14764402307, 14775155089, 15158175701, 15543174253, 17066817083]
_S = [9316335923, 9449790101, 9516794299, 9623130613, 10827521567, 11429419559, 12903836261, 13836097631, 14867317483, 15934126141, 15953196307, 16288509499, 16647947593]

primes = _P + _Q + _R + _S

assert(n == reduce((lambda x, y: x*y), primes))
for prime in primes:
	assert(is_prime(prime))

phi = reduce((lambda x, y: x*y), [prime-1 for prime in primes])
d = invert(e,phi)
m = pow(c,d,n)
print(hex(m)[2:].decode('hex'))