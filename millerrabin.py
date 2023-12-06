from random import randrange

def test_prime(n, witness):
    exp, rem = n - 1, 0
    while not exp & 1:
        exp >>= 1
        rem += 1
    x = pow(witness, exp, n)
    if x == 1 or x == n - 1:
        return True
    for _ in range(rem - 1):
        x = pow(x, 2, n)
        if x == n - 1:
            return True
    return False

def is_prime(n, k = 40):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False

    for _ in range(k):
        witness = randrange(2, n - 1)
        if not test_prime(n, witness):
            return False
    return True

def generate_prime():
    while True:
        prime = (randrange(1 << 1024 - 1, 1 << 1024) << 1) + 1
        if is_prime(prime):
            return prime
