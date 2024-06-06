from math import gcd
import hashlib
import random
import rsa
import time
import multiprocessing

MP = False

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

def server_offline_phase_helper(sj, privkey):
    """Helper function that generates the ts and Ks for each sj in S"""
    hsj = full_domain_hash(sj, privkey.n)
    Ks_j = quick_pow(hsj, privkey.d, privkey.n)
    return (Ks_j, second_hash(Ks_j))

def server_offline_phase(S, privkey):
    """Server computes Ks:j and t_j for each element in its set S."""
    Ks = []
    ts = []
    if MP:
        with multiprocessing.Pool() as pool:
            results = pool.starmap(server_offline_phase_helper, [(sj, privkey) for sj in S])
            for r in results:
                Ks.append(r[0])
                ts.append(r[1])
    else:
        for sj in S:
            ret = server_offline_phase_helper(sj, privkey)
            Ks.append(ret[0])
            ts.append(ret[1])
    return Ks, ts

def client_offline_phase(C, pubkey):
    """Client computes blinded values yi for each element in its set C."""
    ys = []
    Rcs = []
    for ci in C:
        hci = full_domain_hash(ci, pubkey.n)
        Rc = generate_random_zn_star(pubkey.n)
        y = (hci * quick_pow(Rc, pubkey.e, pubkey.n)) % pubkey.n
        ys.append(y)
        Rcs.append(Rc)
    return ys, Rcs

## Online phase

def server_online_phase_helper(y, privkey):
    """Helper function that generates the y_prime for each y in ys"""
    y_prime = quick_pow(y, privkey.d, privkey.n)
    return y_prime

def server_online_phase(ys, privkey):
    """Server computes y'i for each yi received from the client."""
    y_primes = []
    if MP:
        with multiprocessing.Pool() as pool:
            y_primes = pool.starmap(server_online_phase_helper, [(y, privkey) for y in ys])
    else:
        for y in ys:
            y_prime = server_online_phase_helper(y, privkey)
            y_primes.append(y_prime)
    return y_primes

def client_online_phase(y_primes, Rcs, ts, pubkey):
    """Client computes Kc:i and t'i to determine intersections."""
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

## Set Generation Functions

def generate_manual_sets(m, n):
    """Generate sets manually input by the user."""
    client_set = []
    server_set = []
    print(f"Enter {m} elements for the client set:")
    for _ in range(m):
        client_set.append(input())
    print(f"Enter {n} elements for the server set:")
    for _ in range(n):
        server_set.append(input())
    return client_set, server_set

def generate_random_sets(m, n, psi_size):
    """Generate random sets with a specified intersection size."""
    common_elements = random.sample(range(psi_size), psi_size)
    
    remaining_elements_client = random.sample(range(psi_size, psi_size + m), m - psi_size)
    remaining_elements_server = random.sample(range(psi_size + m, psi_size + m + n), n - psi_size)
    
    client_set = [str(i) for i in common_elements + remaining_elements_client]
    server_set = [str(i) for i in common_elements + remaining_elements_server]
    
    random.shuffle(client_set)
    random.shuffle(server_set)
    
    return client_set, server_set

if __name__ == '__main__':
    start_time = time.time()

    # Generate RSA keys
    key_gen_start = time.time()
    pubkey, privkey = generate_keys()
    key_gen_end = time.time()

    # User input for set sizes
    m = int(input("Enter the size of the client set: "))
    n = int(input("Enter the size of the server set: "))

    # User input for set generation method
    method = input("Enter 'M' for manual set input or 'R' for random set generation: ").strip().upper()

    if method == 'M':
        client_set, server_set = generate_manual_sets(m, n)
    elif method == 'R':
        psi_size = int(input("Enter the desired size of the PSI (intersection): "))
        client_set, server_set = generate_random_sets(m, n, psi_size)
    else:
        raise ValueError("Invalid input. Please enter 'M' or 'R'.")

    # Print the generated sets for debugging
    print(f"Client set: {client_set}")
    print(f"Server set: {server_set}")

    # Server offline phase
    server_offline_start = time.time()
    server_keys, server_ts = server_offline_phase(server_set, privkey)
    server_offline_end = time.time()

    # Client offline phase
    client_offline_start = time.time()
    client_ys, client_Rcs = client_offline_phase(client_set, pubkey)
    client_offline_end = time.time()

    # Server online phase (normally this would involve data transmission)
    server_online_start = time.time()
    server_y_primes = server_online_phase(client_ys, privkey)
    server_online_end = time.time()

    # Client computes intersections
    client_online_start = time.time()
    client_t_primes, _, intersection_idxs = client_online_phase(server_y_primes, client_Rcs, server_ts, pubkey)
    client_online_end = time.time()

    total_time = time.time() - start_time

    print("Server hash commitments:", server_ts)
    print("Client hash commitments:", client_t_primes)
    print("Intersection found (via hash commitments):", intersection_idxs)
    print("Intersection found (via hash commitments):", [client_set[idx] for idx in intersection_idxs])

    # Print timing information
    print(f"Total time: {total_time:.6f} seconds")
    print(f"Key generation time: {key_gen_end - key_gen_start:.6f} seconds")
    print(f"Server offline phase time: {server_offline_end - server_offline_start:.6f} seconds")
    print(f"Client offline phase time: {client_offline_end - client_offline_start:.6f} seconds")
    print(f"Server online phase time: {server_online_end - server_online_start:.6f} seconds")
    print(f"Client online phase time: {client_online_end - client_online_start:.6f} seconds")
