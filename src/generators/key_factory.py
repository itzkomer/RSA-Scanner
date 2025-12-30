import os
from math import gcd
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Create directory for keys
OUTPUT_DIR = "vulnerable_keys"
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def save_key(key, filename):
    """Save the key to a PEM file."""
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(os.path.join(OUTPUT_DIR, filename), 'wb') as f:
        f.write(pem)

def extended_gcd(aa, bb):
    """Extended Euclidean Algorithm for finding the modular inverse."""
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

def modinv(a, m):
    """Calculate modular multiplicative inverse."""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError('modular inverse does not exist')
    return x % m

def create_key_from_primes(p, q, e=65537):
    """
    Manual construction of a key object from two given primes.
    Required to artificially generate Shared Primes.
    """
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    
    # Calculate parameters for CRT (Chinese Remainder Theorem)
    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = modinv(q, p)
    
    public_numbers = rsa.RSAPublicNumbers(e, n)
    private_numbers = rsa.RSAPrivateNumbers(
        p=p, q=q, d=d, dmp1=dmp1, dmq1=dmq1, iqmp=iqmp,
        public_numbers=public_numbers
    )
    return private_numbers.private_key(default_backend())

def generate_dataset():
    print(f"Generating 1000 keys in '{OUTPUT_DIR}'...")
    
    # --- 1. Shared Primes Injection (Keys 0 and 1) ---
    print("[+] Injecting Shared Primes vulnerability...")
    # Generate a standard key to extract prime p
    temp_key1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    p_shared = temp_key1.private_numbers().p
    q1 = temp_key1.private_numbers().q
    
    # Generate a second key to extract prime q2 (different from q1)
    temp_key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    q2 = temp_key2.private_numbers().q
    
    # Construct the new keys that share p_shared
    key1 = create_key_from_primes(p_shared, q1)
    key2 = create_key_from_primes(p_shared, q2)
    
    save_key(key1, "key_000_shared_prime_A.pem")
    save_key(key2, "key_001_shared_prime_B.pem")

    # --- 2. Small Primes / Weak Key (Key 2) ---
    print("[+] Injecting Small Key (512 bit)...")
    key_small = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024  # Not secure by today's standards
    )
    save_key(key_small, "key_002_small_512.pem")

    # --- 3. Low Exponent e=3 (Key 3) ---
    print("[+] Injecting Low Exponent (e=3)...")
    # e=3 is very fast but dangerous without proper padding
    try:
        key_low_e = rsa.generate_private_key(
            public_exponent=3,
            key_size=2048
        )
        save_key(key_low_e, "key_003_low_exponent.pem")
    except ValueError:
        print("[-] Note: Some backends might refuse e=3. Retrying with loose check if needed.")

    # --- 4. Generate remaining normal keys ---
    print("[+] Generating remaining standard keys (This may take a moment)...")
    for i in range(4, 1000):
        if i % 100 == 0:
            print(f"   ... generated {i} keys")
        
        # Generate a standard and valid key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        save_key(key, f"key_{i:03d}.pem")

    print(f"\nDone! All keys saved to {OUTPUT_DIR}/")
    print(f"Shared Primes are in: key_000 and key_001")
    print(f"Small Key is: key_002")
    print(f"Low Exponent is: key_003")

if __name__ == "__main__":
    generate_dataset()