from math import gcd
import hashlib
import random
import rsa
import time
import multiprocessing
import argparse

# MP = False

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

def server_offline_phase(S, privkey, num_processes):
    """Server computes Ks:j and t_j for each element in its set S."""
    Ks = []
    ts = []
    if num_processes > 1:
        with multiprocessing.Pool(num_processes) as pool:
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

# def client_offline_phase(C, pubkey):
#     """Client computes blinded values yi for each element in its set C."""
#     ys = []
#     Rcs = []
#     for ci in C:
#         hci = full_domain_hash(ci, pubkey.n)
#         Rc = generate_random_zn_star(pubkey.n)
#         y = (hci * quick_pow(Rc, pubkey.e, pubkey.n)) % pubkey.n
#         ys.append(y)
#         Rcs.append(Rc)
#     return ys, Rcs

def client_offline_phase_helper(ci, pubkey):
    """Helper function for multiprocessing computation in client offline phase."""
    hci = full_domain_hash(ci, pubkey.n)
    Rc = generate_random_zn_star(pubkey.n)
    y = (hci * quick_pow(Rc, pubkey.e, pubkey.n)) % pubkey.n
    return y, Rc


def client_offline_phase(C, pubkey, num_processes):
    """Client computes blinded values yi for each element in its set C using optional multiprocessing."""
    if num_processes > 1:
        with multiprocessing.Pool(num_processes) as pool:
            results = pool.starmap(client_offline_phase_helper, [(ci, pubkey) for ci in C])
            ys, Rcs = zip(*results)
    else:
        ys, Rcs = [], []
        for ci in C:
            y, Rc = client_offline_phase_helper(ci, pubkey)
            ys.append(y)
            Rcs.append(Rc)
    return list(ys), list(Rcs)




## Online phase

def server_online_phase_helper(y, privkey):
    """Helper function that generates the y_prime for each y in ys"""
    y_prime = quick_pow(y, privkey.d, privkey.n)
    return y_prime

def server_online_phase(ys, privkey, num_processes):
    """Server computes y'i for each yi received from the client."""
    y_primes = []
    if num_processes > 1:
        with multiprocessing.Pool(num_processes) as pool:
            y_primes = pool.starmap(server_online_phase_helper, [(y, privkey) for y in ys])
    else:
        for y in ys:
            y_prime = server_online_phase_helper(y, privkey)
            y_primes.append(y_prime)
    return y_primes

# def client_online_phase(y_primes, Rcs, ts, pubkey, _):
#     """Client computes Kc:i and t'i to determine intersections."""
#     t_primes = []
#     intersections = []
#     intersection_ids = []
#     for idx, (y_prime, Rc) in enumerate(zip(y_primes, Rcs)):
#         Kc_i = div_mod(y_prime, Rc, pubkey.n)
#         t_prime = second_hash(Kc_i)
#         t_primes.append(t_prime)
#         if t_prime in ts:
#             intersections.append(t_prime)
#             intersection_ids.append(idx)
#     return t_primes, intersections, intersection_ids



def client_online_phase(y_primes, Rcs, ts, pubkey, num_processes):
    """Client computes Kc:i and t'i to determine intersections using optional multiprocessing."""
    if num_processes > 1:
        with multiprocessing.Pool(num_processes) as pool:
            # Parallel processing
            results = pool.starmap(client_online_phase_helper, [(y_prime, Rc, ts, pubkey) for y_prime, Rc in zip(y_primes, Rcs)])
            t_primes = []
            intersections = []
            intersection_ids = []
            # Collect results, noting intersections and their indices
            for idx, (t_prime, is_intersected) in enumerate(results):
                t_primes.append(t_prime)
                if is_intersected:
                    intersections.append(t_prime)
                    intersection_ids.append(idx)
    else:
        t_primes = []
        intersections = []
        intersection_ids = []
        # Single-threaded processing
        for idx, (y_prime, Rc) in enumerate(zip(y_primes, Rcs)):
            t_prime, is_intersected = client_online_phase_helper(y_prime, Rc, ts, pubkey)
            t_primes.append(t_prime)
            if is_intersected:
                intersections.append(t_prime)
                intersection_ids.append(idx)

    return t_primes, intersections, intersection_ids

def client_online_phase_helper(y_prime, Rc, ts, pubkey):
    """Helper function for multiprocessing computation in client online phase."""
    Kc_i = div_mod(y_prime, Rc, pubkey.n)
    t_prime = second_hash(Kc_i)
    is_intersected = t_prime in ts
    return t_prime, is_intersected




## Set Generation Functions

def generate_manual_sets(filename):
    """Generate sets manually from a given file."""
    with open(filename, 'r') as file:
        lines = file.read().splitlines()
    mid = len(lines) // 2
    client_set = lines[:mid]
    server_set = lines[mid:]
    return client_set, server_set


def generate_random_sets(m, n, psi_size, filename):
    BIG_NUM = int(1e9)

    if psi_size > m or psi_size > n:
        raise ValueError("Intersection size cannot exceed set sizes.")
    
    range_size =  BIG_NUM // 3
    if (2 * (m + n) - psi_size) > BIG_NUM or (m - psi_size) > range_size or (n - psi_size) > range_size:
        raise ValueError("Requested number of elements exceeds the max allowable range.")

    
    
    common_elements = random.sample(range(range_size), psi_size)
    remaining_elements_server = random.sample(range(2 * range_size, 3 * range_size), n - psi_size)
    remaining_elements_client = random.sample(range(range_size, 2 * range_size), m - psi_size)

    client_set = [str(i) for i in common_elements + remaining_elements_client]
    server_set = [str(i) for i in common_elements + remaining_elements_server]

    
    random.shuffle(client_set)
    random.shuffle(server_set)
    
    with open(filename, 'w') as file:
        file.write('\n'.join(client_set + server_set))
    
    return client_set, server_set


def prepare_data(args):
    if args.method == 'M':
        if not args.filename:
            raise ValueError("Filename required for manual input.")
        client_set, server_set = generate_manual_sets(args.filename)
    elif args.method == 'R':
        if not args.filename:
            raise ValueError("Filename required for saving random sets.")
        if args.psi_size is None:
            raise ValueError("PSI size is required for random set generation.")
        client_set, server_set = generate_random_sets(args.m, args.n, args.psi_size, args.filename)
    else:
        raise ValueError("Invalid method. Please choose 'M' or 'R'.")
    
    return client_set, server_set

def perform_computation(client_set, server_set, pubkey, privkey, args):
    timings = {}
    
    # Server offline phase
    start_time = time.time()
    server_keys, server_ts = server_offline_phase(server_set, privkey, args.mp)
    timings['server_offline'] = time.time() - start_time

    # Client offline phase
    start_time = time.time()
    client_ys, client_Rcs = client_offline_phase(client_set, pubkey, args.mp)
    timings['client_offline'] = time.time() - start_time

    # Server online phase
    start_time = time.time()
    server_y_primes = server_online_phase(client_ys, privkey, args.mp)
    timings['server_online'] = time.time() - start_time

    # Client computes intersections
    start_time = time.time()
    client_t_primes, _, intersection_idxs = client_online_phase(server_y_primes, client_Rcs, server_ts, pubkey, args.mp)
    timings['client_online'] = time.time() - start_time

    return intersection_idxs, timings

def main(args):
    start_time = time.time()

    # Generate RSA keys
    pubkey, privkey = generate_keys()

    # Prepare data based on method
    client_set, server_set = prepare_data(args)

    # Perform cryptographic computations
    intersection_idxs, timings = perform_computation(client_set, server_set, pubkey, privkey, args)

    # Calculate total time and print timing information
    total_time = time.time() - start_time
    print(f"Total time: {total_time:.6f} seconds")
    for phase, duration in timings.items():
        print(f"{phase.capitalize()} phase time: {duration:.6f} seconds")
    
    # Optional: Display intersections
    res = [client_set[idx] for idx in intersection_idxs]
    res = set(res)
    print("Intersections:", res)

    if len(intersection_idxs) != args.psi_size:
        # ground_truth = set(client_set).intersection(server_set)
        # print(f"Ground truth [size={len(ground_truth)}]: {ground_truth}")
        raise ValueError("Incorrect intersection size result")

    return res


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Generate and manage sets for PSI")
    parser.add_argument('m', type=int, help="Size of the client set")
    parser.add_argument('n', type=int, help="Size of the server set")
    parser.add_argument('--method', choices=['M', 'R'], required=True, help="Method to generate sets: 'M' for manual, 'R' for random")
    parser.add_argument('--filename', help="Filename to load from or save to")
    parser.add_argument('--psi_size', type=int, help="Desired size of the intersection for random generation")
    parser.add_argument('--mp', type=int, default=1, help="Number of processes for multiprocessing (default is 1, which is single-threaded)")

    args = parser.parse_args()
    main(args)