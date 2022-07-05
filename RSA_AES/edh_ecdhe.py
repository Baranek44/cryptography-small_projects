from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def use_edh():
    # Generate public DH parameters
    # 512 only for demo, in prodyctions it would be 2048 bits
    dh_parameters = dh.generate_parameters(generator=2, key_size=512)
    g = dh_parameters.parameter_numbers().g
    p = dh_parameters.parameter_numbers().p

    # Generate public-private key of Person1
    private_key_a = dh_parameters.generate_private_key()
    public_key_a = private_key_a.public_key()

    x = private_key_a.private_numbers().x
    a = public_key_a.public_numbers().y
    assert (a == pow(g, x, p))

    # Generate public-private key of Person2
    private_key_b = dh_parameters.generate_private_key()
    public_key_b = private_key_b.public_key()

    y = private_key_b.private_numbers().x
    b = public_key_b.public_numbers().y
    assert (b == pow(g, y, p))

    # Generate  shared key of Person1
    shared_key_person1 = private_key_a.exchange(public_key_b)

    k_a = int.from_bytes(shared_key_person1, 'big')
    assert (k_a == pow(b, x, p))

    # Generate shared key fo Person2
    shared_key_person2 = private_key_b.exchange(public_key_a)

    k_b = int.from_bytes(shared_key_person1, 'big')
    assert (k_b == pow(b, x, p))

    # Verify Person1 and Person2 arrived at the same shared key
    assert (shared_key_person2 == shared_key_person1)


def use_ecdhe():

    # X25519, which is ECDHE working against Curve25519
    # Generate public-private key of Person1
    private_key_a = X25519PrivateKey.generate()
    public_key_a = private_key_a.public_key()

    # Generate public-private  key of Person2
    private_key_b = X25519PrivateKey.generate()
    public_key_b = private_key_b.public_key()

    # Generate shared key of Person1
    shared_key_a = private_key_a.exchange(public_key_b)

    # Generate shared key of Person2
    shared_key_b = private_key_b.exchange(public_key_a)

    # Verify Person1 and Person2 arrived at the same shared key
    assert (shared_key_a == shared_key_b)


if __name__ == "__main__":

    use_edh()
    use_ecdhe()