# RSA-Scanner

### Large-Scale Cryptanalysis Framework for Detecting Shared Prime Vulnerabilities

## Overview

**RSA-Scanner** is an algorithmic security tool designed to audit large datasets of RSA public keys. It implements **Bernstein's Batch GCD algorithm** to efficiently detect the "Shared Prime" vulnerability across thousands of keys.

Unlike naive pairwise comparison which scales at , this tool utilizes a **Product Tree** approach to reduce complexity to approximately , making it feasible to analyze massive datasets (such as TLS certificate transparency logs or SSH host keys).

## The Math

RSA security relies on the difficulty of factoring .
However, if two distinct moduli  and  share a prime factor  (usually due to poor entropy during key generation), we can trivially compute the factor:

Once  is found, the private key  can be recovered immediately using the extended Euclidean algorithm to derive the modular inverse.

### Performance Analysis

This implementation was tested against a naive pairwise scanner. The results demonstrate the efficiency of the Product Tree approach:

| Dataset Size | Naive GCD () | Batch GCD (My Algo) |
| --- | --- | --- |
| **100 Keys** | 0.4s | **0.05s** |
| **1,000 Keys** | ~45.0s | **~1.2s** |
| **10,000 Keys** | *(Estimated: >1 hour)* | **~15.0s** |

## Features

* **Synthetic Dataset Generator:** Creates "poisoned" RSA keys (Shared Primes, Low Exponent, Small Key Sizes) for validation.
* **Batch GCD Engine:** Optimized Python implementation of Product Tree & Remainder Tree logic.
* **Auto-Exploitation:** Automatically derives the private key () upon detecting a vulnerability.
* **Modular Architecture:** Separated logic for generation, attack, and analysis.

## Usage

### 1. Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/YOUR_USERNAME/RSA-Weakness-Scanner.git
cd RSA-Weakness-Scanner
pip install -r requirements.txt

```

### 2. Generate Vulnerable Data (Lab Mode)

Create a dataset of 1,000 keys with injected vulnerabilities:

```bash
python3 main.py --generate

```

### 3. Run the Scanner

Execute the Batch GCD attack to identify weak keys and recover private exponents:

```bash
python3 main.py --scan

```

## Project Structure

```text
RSA-Scanner/
├── src/
│   ├── attacks/
│   │   └── batch_gcd.py       # Core Bernstein's algorithm implementation
│   ├── generators/
│   │   └── generate_keys.py   # Factory for creating weak cryptographic keys
│   └── utils/
│       └── math_helpers.py    # Modular inverse and GCD helpers
├── notebooks/                 # Research analysis and performance graphs
├── vulnerable_keys/           # Output directory for generated PEM files
├── main.py                    # CLI Entry point
├── requirements.txt           # Dependencies
└── README.md

```
