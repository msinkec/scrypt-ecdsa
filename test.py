from bitcoinx import PrivateKey, SigHash, double_sha256, pack_byte
from scryptlib import Bytes, compile_contract, build_contract_class


if __name__ == '__main__':
    key_priv = PrivateKey.from_arbitrary_bytes(b'test123')
    key_pub = key_priv.public_key

    msg = 'Hello, World!'
    msg_bytes = str.encode(msg, encoding='ASCII')

    # Create signature
    sig = key_priv.sign(msg_bytes, hasher=double_sha256)

    # Verify signature in Python
    assert key_pub.verify_der_signature(sig, msg_bytes, hasher=double_sha256)

    # Point addition
    to_add = PrivateKey.from_arbitrary_bytes(b'bla')
    point_sum = key_pub.add(to_add._secret)
    assert point_sum.to_hex(compressed=True) == '0210665ad464f2b7a382841d7f764044877db2c988240149a2b1c0e330df5c6f26'

    # Point doubling
    point_doubled = key_pub.add(key_priv._secret)
    assert point_doubled.to_hex(compressed=True) == '02d955f9f2eb090bcda5f0f158d569880dbe307cfac6a982b674116f7cf013b875'

    # Scalar multiplication (small)
    s = PrivateKey.from_int(1)
    point_scaled = key_pub.multiply(s._secret)
    assert point_scaled.to_hex(compressed=True) == '02aadd9a74b2fe14aa90c0a4e26422959d50acfc64d6c73bf0efcf218c3f66d447'
    
    ############################
    #################### sCrypt

    contract = './checksig.scrypt'

    compiler_result = compile_contract(contract)
    desc = compiler_result.to_desc()

    TestCheckSig = build_contract_class(desc)
    testCheckSig = TestCheckSig()

    # Point addition
    ax, ay = key_pub.to_point()
    bx, by = to_add.public_key.to_point()
    sumx, sumy = point_sum.to_point()

    assert testCheckSig.testAdd(
                ax, ay, bx, by, sumx, sumy
            ).verify()

    # Point doubling
    dx, dy = point_doubled.to_point()

    assert testCheckSig.testDouble(
                ax, ay, dx, dy
            ).verify()

    # Point doubling, point at inf
    assert testCheckSig.testDouble(
                0, 0, 0, 0
            ).verify()


    # Point addition, same point
    assert testCheckSig.testAdd(
                ax, ay, ax, ay, dx, dy
            ).verify()


    # TODO: Scalar multiplication


    # Point addition with many random keys
    for i in range(500):
        print("Adding rand key, iter. {}".format(i))
        rand_key_priv = PrivateKey.from_random()
        rand_to_add = PrivateKey.from_random()
        rand_point_sum = rand_key_priv.public_key.add(rand_to_add._secret)

        rax, ray = rand_key_priv.public_key.to_point()
        rbx, rby = rand_to_add.public_key.to_point()
        rsumx, rsumy = rand_point_sum.to_point()

        assert testCheckSig.testAdd(
                    rax, ray, rbx, rby, rsumx, rsumy
                ).verify()

    # Point double with many random keys
    for i in range(500):
        print("Doubling rand key, iter. {}".format(i))
        rand_key_priv = PrivateKey.from_random()
        rand_point_sum = rand_key_priv.public_key.add(rand_key_priv._secret)

        rax, ray = rand_key_priv.public_key.to_point()
        rsumx, rsumy = rand_point_sum.to_point()

        assert testCheckSig.testDouble(
                    rax, ray, rsumx, rsumy
                ).verify()


