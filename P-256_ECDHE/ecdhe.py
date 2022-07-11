import os


class ECurve:
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p

    def inf(self):
        return ECPoint(curve=self, x=None, y=None)

    def __eq__(self, other):
        return self.a == other.a and self.b == other.b and self.p == other.p


class ECPoint:
    def __init__(self, curve, x, y):
        self.curve = curve
        self.x = x
        self.y = y

    def is_inf(self):
        return self == self.curve.inf()

    def copy(self):
        return ECPoint(curve=self.curve, x=self.x, y=self.y)

    def __eq__(self, other):
        return self.curve == other.curve and self.x == other.x and self.y == other.y

    def __mul__(self, s):
        bits = [s & (1 << i) for i in range(s.bit_length() - 1, -1, -1)]
        res = self.curve.inf()
        for bit in bits:
            res = res + res
            if bit:
                res = res + self
        return res

    def __add__(self, other):
        if self.is_inf():
            return other.copy()
        if other.is_inf():
            return self.copy()
        x1, y1 = self.x, self.y
        x2, y2 = other.x, other.y
        p = self.curve.p
        if x1 % p == x2 % p and y1 % p == (-y2) % p:
            return self.curve.inf()
        if self != other:
            s = (y2 - y1) * pow(x2 - x1, -1, p) % p
        else:
            s = (3 * pow(x1, 2) + self.curve.a) * pow(2 * y1, -1, p) % p
        x3 = (pow(s, 2) - x1 - x2) % p
        y3 = (s * (x1 - x3) - y1) % p
        return ECPoint(curve=self.curve, x=x3, y=y3)


def generate_random_p_256_secret(n):
    condidate = 0
    while not 0 < condidate < n:
        condidate = int.from_bytes(os.urandom((n.bit_length() + 7) // 8), 'big')
    return condidate


if __name__ == '__main__':
    # NIST P-256
    p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
    n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
    a = 115792089210356248762697446949407573530086143415290314195533631308867097853948
    b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
    Gx = 48439561293906451759052585252797914202762949526041747995844080717082404635286
    Gy = 36134250956749795798585127919587881956611106672985015071877198253568414405109

    # Create curve and generate point 6
    p_256_curve = ECurve(a, b, p)
    G = ECPoint(p_256_curve, Gx, Gy)

    # Public-private key of Person1
    private_key_person1 = generate_random_p_256_secret(n)
    public_key_person1 = G * private_key_person1

    # Public_private key of Person2
    private_key_person2 = generate_random_p_256_secret(n)
    public_key_person2 = G * private_key_person2

    # Shared key of Person1
    shared_key_person1 = public_key_person2 * private_key_person1

    # Shared key of Person2
    shared_key_person2 = public_key_person1 * private_key_person2

    # Verify both Person1 and Person2 arrived at the same shared key
    assert (shared_key_person2 == shared_key_person1)
