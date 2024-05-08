from math import gcd
import hashlib
import random
import rsa


## Helper functions

def quick_pow(x, y, mod):
    """Quickly computes x^y % mod."""
    result = 1
    while y:
        if y & 1:
            result = (result * x) % mod
        y >>= 1
        x = (x * x) % mod
    return result

def modinv(a, n):
    """Compute the modular inverse of a under modulus n."""
    g, x, _ = rsa.common.extended_gcd(a, n)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % n

def div_mod(a, b, n):
    """Compute a/b mod n."""
    return (a * modinv(b, n)) % n


def full_domain_hash(message, n):
    """Hashes the message to an integer in Z_n*."""
    digest = hashlib.sha256(message.encode()).digest()
    return int.from_bytes(digest, 'big') % n

def second_hash(value):
    """Applies a secondary hash for commitments."""
    return hashlib.sha256(value.to_bytes((value.bit_length() + 7) // 8, byteorder='big')).hexdigest()

def generate_random_zn_star(n):
    """Generate a random number in Z_n*."""
    while True:
        r = random.randint(2, n - 2)
        if gcd(r, n) == 1:
            return r


## Key generation

def generate_keys():
    """Generate RSA keys."""
    (pubkey, privkey) = rsa.newkeys(2048)
    return pubkey, privkey

## Offline phase

def server_offline_phase(S, privkey):
    """Server computes Ks:j and t_j for each element in its set S."""
    Ks = []
    ts = []
    for sj in S:
        hsj = full_domain_hash(sj, privkey.n)
        # hsj = quick_pow(full_domain_hash(sj, privkey.n), privkey.d, privkey.n)
        # Ks_j = rsa.core.decrypt_int(hsj, privkey.d, privkey.n)
        Ks_j = quick_pow(hsj, privkey.d, privkey.n)
        ts.append(second_hash(Ks_j))
        Ks.append(Ks_j)
    return Ks, ts


def client_offline_phase(C, pubkey):
    """Client computes blinded values yi for each element in its set C."""
    ys = []
    Rcs = []
    # Z_n_star = generate_random_zn_star(pubkey.n)
    for ci in C:
        hci = full_domain_hash(ci, pubkey.n)
        Rc_i = generate_random_zn_star(pubkey.n)
        yi = (hci * quick_pow(Rc_i, pubkey.e, pubkey.n)) % pubkey.n
        ys.append(yi)
        Rcs.append(Rc_i)
    return ys, Rcs


## Online phase
def server_online_phase(ys, privkey):
    """Server computes y_i' from received y_i."""
    y_primes = [quick_pow(yi, privkey.d, privkey.n) for yi in ys]
    return y_primes

def client_online_phase(y_primes, Rcs, ts, pubkey):
    """Client computes t_i' and finds intersections."""
    t_primes = []
    intersections = []
    intersection_ids = []
    for idx, (y_prime, Rc) in enumerate(zip(y_primes, Rcs)):
        Kc_i = div_mod(y_prime, Rc, pubkey.n)
        t_prime = second_hash(Kc_i)
        t_primes.append(t_prime)
        if t_prime in ts:
            intersections.append(t_prime)
            intersection_ids.append(idx)
    return t_primes, intersections, intersection_ids


# def decrypt_intersections(intersections, originial_set):
#     """Decrypt the intersections."""
#     decrypted_intersections = []
#     for intersection in intersections:
#         decrypted_intersection = quick_pow(int(intersection, 16), privkey.d, privkey.n)
#         decrypted_intersections.append(decrypted_intersection)
#     return decrypted_intersections

## Test
if __name__ == '__main__':
    # Generate RSA keys
    pubkey, privkey = generate_keys()

    # Define the sets for the client and server
    client_set = ["apple", "banana", "cherry", "date"]
    server_set = ["banana", "date", "fig", "grape"]

    # Print initial sets
    print("Client Set:", client_set)
    print("Server Set:", server_set)

    # Server offline phase
    server_keys, server_ts = server_offline_phase(server_set, privkey)

    # Client offline phase
    client_ys, client_Rcs = client_offline_phase(client_set, pubkey)

    # Server online phase (normally this would involve data transmission)
    server_y_primes = server_online_phase(client_ys, privkey)

    # Client computes intersections
    client_t_primes, _,  intersection_idxs = client_online_phase(server_y_primes, client_Rcs, server_ts, pubkey)

    # Print results
    # Print the results
    print("Server hash commitments:", server_ts)
    print("Client hash commitments:", client_t_primes)
    print("Intersection found (via hash commitments):", intersection_idxs)

    # Decrypt the intersections
    print("Intersection found (via hash commitments):", [client_set[idx] for idx in intersection_idxs])



