import argparse
import sys
import time
import os

# Import modules from your project structure
# Assumes structure:
# src/
#   generators/
#      key_factory.py
#   attacks/
#      batch_gcd.py

try:
    from src.generators import key_factory
    from src.attacks import batch_gcd
except ImportError as e:
    print("Error importing modules. Make sure you have '__init__.py' files in your 'src' directories.")
    print(f"Details: {e}")
    sys.exit(1)

# ANSI Colors for professional output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"


def run_generation():
    """Wrapper to run the key generation module."""
    print(f"{YELLOW}[*] Mode: Dataset Generation{RESET}")
    start_time = time.time()
    
    # Call the function from src/generators/key_factory.py
    try:
        key_factory.generate_dataset()
        print(f"{GREEN}[+] Generation complete in {time.time() - start_time:.2f} seconds.{RESET}")
    except Exception as e:
        print(f"{RED}[-] Generation failed: {e}{RESET}")

def run_scan(directory):
    """Wrapper to run the attack module."""
    print(f"{YELLOW}[*] Mode: Vulnerability Scan{RESET}")
    print(f"{YELLOW}[*] Target Directory: {directory}{RESET}")
    
    # 1. Load Keys
    try:
        # Note: We need to ensure load_moduli accepts a path or uses a default
        # Assuming we modified batch_gcd.load_moduli to take a path argument
        # If your script has hardcoded path, you might need to adjust this part.
        
        # Let's assume you updated batch_gcd.py to allow passing the directory, 
        # or we temporarily set the global var if the module allows it.
        # For now, we will call the loading function from the module.
        if hasattr(batch_gcd, 'KEYS_DIR'):
            batch_gcd.KEYS_DIR = directory # Override default dir
            
        moduli, filenames = batch_gcd.load_moduli()
    except FileNotFoundError:
        print(f"{RED}[-] Directory not found: {directory}{RESET}")
        return
    except Exception as e:
        print(f"{RED}[-] Error loading keys: {e}{RESET}")
        return

    if not moduli:
        print(f"{RED}[-] No keys found in directory.{RESET}")
        return

    print(f"{CYAN}[i] Loaded {len(moduli)} public keys.{RESET}")

    # 2. Run Batch GCD Attack
    start_time = time.time()
    gcd_results = batch_gcd.batch_gcd(moduli)
    duration = time.time() - start_time

    # 3. Analyze Results
    print(f"\n{YELLOW}[*] Analysis Results ({duration:.4f}s):{RESET}")
    print("-" * 70)
    print(f"{'Filename':<30} | {'Status':<15} | {'Details'}")
    print("-" * 70)

    n_to_filename = {n: name for n, name in zip(moduli, filenames)}
    vulnerable_count = 0

    for n in moduli:
        g = gcd_results.get(n, 1)
        fname = n_to_filename[n]
        
        if g > 1 and g < n:
            vulnerable_count += 1
            print(f"{RED}{fname:<30} | VULNERABLE      | Shared Factor: {str(g)[:15]}...{RESET}")
            
            # Attempt to recover Private Key if the function exists
            if hasattr(batch_gcd, 'recover_private_key'):
                d = batch_gcd.recover_private_key(n, g)
                if d:
                    print(f"{GREEN}{' ':<30} | EXPLOITED       | Private Key (d) Recovered!{RESET}")
        
        elif g == n:
             # Duplicate key scenario
             pass 

    print("-" * 70)
    if vulnerable_count > 0:
        print(f"{RED}[!] FAILURE: Found {vulnerable_count} compromised keys.{RESET}")
        print(f"{CYAN}[i] Mathematical Insight: Using Batch-GCD reduced complexity from O(N^2) to O(N log^2 N).{RESET}")
    else:
        print(f"{GREEN}[v] SUCCESS: No shared factors detected.{RESET}")

def main():
    parser = argparse.ArgumentParser(description="RSA Algorithmic Weakness Scanner")
    
    # Define arguments
    parser.add_argument('--generate', action='store_true', help='Generate synthetic vulnerable dataset')
    parser.add_argument('--scan', action='store_true', help='Scan a directory of keys for vulnerabilities')
    parser.add_argument('--dir', type=str, default='vulnerable_keys', help='Directory containing PEM keys')
    
    args = parser.parse_args()
    

    if args.generate:
        run_generation()
    
    elif args.scan:
        run_scan(args.dir)
        
    else:
        # Default behavior if no flags provided
        parser.print_help()

if __name__ == "__main__":
    main()