import os
import math
from cryptography.hazmat.primitives import serialization

KEYS_DIR = "vulnerable_keys"

class ProductTreeNode:
    """Represents a node in the Product Tree."""
    def __init__(self, value, left=None, right=None):
        self.value = value
        self.left = left
        self.right = right

def load_moduli():
    """Loads all moduli from the PEM files in the directory."""
    moduli = []
    filenames = []
    
    print(f"[+] Loading keys from {KEYS_DIR}...")
    files = sorted([f for f in os.listdir(KEYS_DIR) if f.endswith('.pem')])
    
    for f_name in files:
        with open(os.path.join(KEYS_DIR, f_name), "rb") as key_file:
            try:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )
                # Extract modulus N
                n = private_key.private_numbers().public_numbers.n
                moduli.append(n)
                filenames.append(f_name)
            except Exception as e:
                print(f"[-] Error loading {f_name}: {e}")
                
    return moduli, filenames

def product_tree(moduli):
    """
    Step 1: Build the Product Tree.
    """
    nodes = [ProductTreeNode(n) for n in moduli]
    
    while len(nodes) > 1:
        next_level = []
        for i in range(0, len(nodes), 2):
            if i + 1 < len(nodes):
                prod = nodes[i].value * nodes[i+1].value
                parent = ProductTreeNode(prod, left=nodes[i], right=nodes[i+1])
                next_level.append(parent)
            else:
                next_level.append(nodes[i])
        nodes = next_level
        
    return nodes[0]

def remainder_tree(node, x, results_map):
    """
    Step 2: Descend the tree and calculate remainders.
    """
    if node.left is None and node.right is None:
        n = node.value
        g = math.gcd(n, x // n)
        results_map[n] = g
        return

    if node.left:
        val_left = x % (node.left.value ** 2)
        remainder_tree(node.left, val_left, results_map)

    if node.right:
        val_right = x % (node.right.value ** 2)
        remainder_tree(node.right, val_right, results_map)

def batch_gcd(moduli):
    """Wrapper function running the full Batch GCD algorithm."""
    if not moduli:
        return {}
        
    print("[+] Building Product Tree (Step 1/3)...")
    root = product_tree(moduli)
    
    print("[+] Calculating Remainder Tree (Step 2/3)...")
    results = {}
    remainder_tree(root, root.value, results)
    
    return results

def recover_private_key(n, p, e=65537):
    """
    Given the public modulus n, public exponent e, and a known prime factor p,
    recover the private key d.
    """
    try:
        q = n // p
        phi = (p - 1) * (q - 1)
        
        # חישוב ההופכי המודולרי (Modular Inverse)
        # d = e^-1 mod phi
        # Note: pow(base, -1, mod) requires Python 3.8+
        d = pow(e, -1, phi) 
        
        return d
    except Exception as e:
        print(f"[-] Failed to recover key: {e}")
        return None

def main():
    moduli, filenames = load_moduli()
    print(f"[i] Loaded {len(moduli)} keys.")
    
    n_to_filename = {n: name for n, name in zip(moduli, filenames)}
    
    gcd_results = batch_gcd(moduli)
    
    print("[+] Analyzing results (Step 3/3)...")
    print("-" * 80)
    print(f"{'Filename':<30} | {'Status':<15} | {'Factor / Recovery Info'}")
    print("-" * 80)
    
    vulnerable_count = 0
    for n in moduli:
        g = gcd_results.get(n, 1)
        fname = n_to_filename[n]
        
        if g > 1 and g < n:
            # Shared factor found!
            print(f"\033[91m{fname:<30} | VULNERABLE      | Factor: {str(g)[:15]}...\033[0m")
            
            recovered_d = recover_private_key(n, g)
            if recovered_d:
                 print(f"                               |                 | \033[92m[!] Private Key Recovered!\033[0m")
                 print(f"                               |                 | \033[92m[!] d = {str(recovered_d)[:20]}...\033[0m")            
            vulnerable_count += 1

        elif g == n:
             print(f"{fname:<30} | DUPLICATE KEY   | -")
        else:
             pass

    print("-" * 80)
    print(f"[+] Scan Complete. Found and exploited {vulnerable_count} keys.")

if __name__ == "__main__":
    main()