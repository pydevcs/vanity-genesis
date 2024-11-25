import argparse
from bip_utils import (
    Bip39MnemonicGenerator,
    Bip39WordsNum,
    Bip39SeedGenerator,
    Bip84,
    Bip84Coins,
    Bip44,
    Bip44Coins,
    Bip44Changes
)
import re
import sys
import os
import time
import math

def valid_segwit_str(substring: str) -> bool:
    """
    Check if a substring could potentially be part of a valid SegWit address.
    """
    # SegWit addresses are case-insensitive and use base32 characters.
    # Valid characters: '023456789acdefghjklmnpqrstuvwxyz' (excluding '1', 'b', 'i', 'o')
    return re.match(r'^[023456789acdefghjklmnpqrstuvwxyz]*$', substring) is not None

def valid_eth_str(substring: str) -> bool:
    """
    Check if a substring could potentially be part of a valid Ethereum address.
    """
    # Ethereum addresses are in hexadecimal, which allows characters: '0-9', 'a-f', 'A-F'.
    return re.match(r'^[0-9a-fA-F]*$', substring) is not None

def generate_segwit_address(mnemonic, account_index=0, address_index=0, passphrase="", network="mainnet"):
    """
    Generate a native SegWit (P2WPKH) Bitcoin address for the specified network.
    """
    try:
        # Generate seed from mnemonic
        seed_gen = Bip39SeedGenerator(mnemonic)
        seed = seed_gen.Generate(passphrase)

        # Choose the network
        coin_type = Bip84Coins.BITCOIN if network == "mainnet" else Bip84Coins.BITCOIN_TESTNET

        # Create BIP84 (native SegWit) derivation object
        bip84_mst_ctx = Bip84.FromSeed(seed, coin_type)

        # Derive account key
        bip84_acc_ctx = bip84_mst_ctx.Purpose().Coin().Account(account_index)

        # Derive specific address
        bip84_chg_ctx = bip84_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
        bip84_addr_ctx = bip84_chg_ctx.AddressIndex(address_index)

        # Get the public key and generate address
        pub_key = bip84_addr_ctx.PublicKey().ToAddress()

        # Get the address details
        return {
            "mnemonic": mnemonic,
            "seed_hex": seed.hex(),
            "xpub": bip84_acc_ctx.PublicKey().ToExtended(),
            "address": pub_key,
            "private_key": bip84_addr_ctx.PrivateKey().ToWif()
        }

    except Exception as e:
        print(f"Error generating SegWit address: {e}")
        raise

def generate_ethereum_address(mnemonic, account_index=0, address_index=0, passphrase=""):
    """
    Generate an Ethereum address.
    """
    try:
        # Generate seed from mnemonic
        seed_gen = Bip39SeedGenerator(mnemonic)
        seed = seed_gen.Generate(passphrase)

        # Create BIP44 derivation object for Ethereum
        bip44_mst_ctx = Bip44.FromSeed(seed, Bip44Coins.ETHEREUM)

        # Derive account key
        bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(account_index)

        # Derive specific address
        bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
        bip44_addr_ctx = bip44_chg_ctx.AddressIndex(address_index)

        # Get the address details
        return {
            "mnemonic": mnemonic,
            "seed_hex": seed.hex(),
            "address": bip44_addr_ctx.PublicKey().ToAddress(),
            "private_key": bip44_addr_ctx.PrivateKey().Raw().ToHex()
        }

    except Exception as e:
        print(f"Error generating Ethereum address: {e}")
        raise

def calculate_search_space(search_term: str, coin_type: str) -> int:
    """
    Calculate the size of the search space for a given search term.
    """
    if coin_type == "bitcoin":
        # Base32 character set for SegWit addresses
        chars_per_position = 32
    else:  # ethereum
        # Hex character set for Ethereum addresses
        chars_per_position = 16
    
    return chars_per_position ** len(search_term)

def estimate_time(single_attempt_time: float, search_space: int) -> dict:
    """
    Estimate the time needed to find a match based on search space and single attempt time.
    """
    # On average, we'll find a match halfway through the search space
    average_attempts = search_space / 2
    
    estimated_seconds = average_attempts * single_attempt_time
    
    return {
        "attempts_needed": average_attempts,
        "estimated_seconds": estimated_seconds,
        "estimated_minutes": estimated_seconds / 60,
        "estimated_hours": estimated_seconds / 3600,
        "estimated_days": estimated_seconds / (3600 * 24)
    }

def measure_single_generation(coin_type: str, network="mainnet") -> float:
    """
    Measure the time taken to generate a single address.
    """
    start_time = time.time()
    
    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)
    
    if coin_type == "bitcoin":
        generate_segwit_address(mnemonic, network=network)
    else:
        generate_ethereum_address(mnemonic)
        
    end_time = time.time()
    return end_time - start_time

def analyze_vanity_generation(search_term: str, coin_type: str, network="mainnet") -> dict:
    """
    Analyze the time and probability for generating a vanity address.
    """
    # Validate search term
    if coin_type == "bitcoin" and not valid_segwit_str(search_term):
        raise ValueError("Invalid search term for Bitcoin SegWit address")
    elif coin_type == "ethereum" and not valid_eth_str(search_term):
        raise ValueError("Invalid search term for Ethereum address")
    
    # Measure time for a single generation
    single_time = measure_single_generation(coin_type, network)
    
    # Calculate search space
    search_space = calculate_search_space(search_term, coin_type)
    
    # Estimate total time needed
    time_estimates = estimate_time(single_time, search_space)
    
    return {
        "single_generation_time": single_time,
        "search_space_size": search_space,
        **time_estimates
    }

def print_analysis(analysis: dict, search_term: str, coin_type: str):
    """
    Print the analysis results in a readable format.
    """
    print(f"\nVanity Address Analysis for '{search_term}' ({coin_type})")
    print("-" * 50)
    print(f"Single address generation time: {analysis['single_generation_time']:.4f} seconds")
    print(f"Search space size: {analysis['search_space_size']:,} possibilities")
    print(f"Average attempts needed: {analysis['attempts_needed']:,.0f}")
    print("\nEstimated time to find match:")
    print(f"  Seconds: {analysis['estimated_seconds']:,.2f}")
    print(f"  Minutes: {analysis['estimated_minutes']:,.2f}")
    print(f"  Hours: {analysis['estimated_hours']:,.2f}")
    print(f"  Days: {analysis['estimated_days']:,.2f}\r\n")

def main():
    parser = argparse.ArgumentParser(description="Generate Bitcoin or Ethereum addresses.")
    parser.add_argument(
        "search_term",  # Positional argument
        help="The search string to use."
    )
    parser.add_argument(
        "--coin", choices=["bitcoin", "ethereum"], default="bitcoin",
        help="Specify the cryptocurrency for address generation."
    )
    parser.add_argument(
        "--network", choices=["mainnet", "testnet"], default="mainnet",
        help="Specify the network type (mainnet or testnet, default: mainnet)."
    )
    parser.add_argument(
        "--wordcount", type=int, choices=[12, 15, 18, 21, 24], default=12,
        help="Number of words in the mnemonic (default: 12)."
    )
    parser.add_argument(
        "--match_type", type=int, choices=[0,1], default=1,
        help="0 matches search_term anywhere in the address, while 1 matches to the prefix."
    )
    parser.add_argument(
        "--pw", type=str, default="",  # Default is an empty string
        help="An optional passphrase for additional security or functionality (default: '')."
    )
    args = parser.parse_args()

    try:
        analysis = analyze_vanity_generation(args.search_term, args.coin, args.network)
        print_analysis(analysis, args.search_term, args.coin)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Generate a mnemonic with the specified word count
    words_num_map = {
        12: Bip39WordsNum.WORDS_NUM_12,
        15: Bip39WordsNum.WORDS_NUM_15,
        18: Bip39WordsNum.WORDS_NUM_18,
        21: Bip39WordsNum.WORDS_NUM_21,
        24: Bip39WordsNum.WORDS_NUM_24
    }

    if args.search_term == None:
        print('Please include a search term.')
        return

    address_matched = False

    hash_count = 0

    while True:
        mnemonic = Bip39MnemonicGenerator().FromWordsNumber(words_num_map[args.wordcount])

        hash_count += 1

        if args.coin == "bitcoin":
            if not valid_segwit_str(args.search_term):
                print('Invalid search term.')
                return
            address_info = generate_segwit_address(mnemonic, network=args.network, passphrase=args.pw)
            if args.match_type == 0:
                if address_info['address'][4:(len(args.search_term) + 4)] == args.search_term:
                    address_matched = True
            else:
                if args.search_term in address_info['address'][4:]:
                    address_matched = True

            if address_matched:
                # Clear the line and print the final details
                sys.stdout.write('\033[2K\033[1G')  # Clear the line and move cursor to the beginning
                print(f"Found vanity seed after {'{:,}'.format(hash_count)} Hashes")
                print(f"Bitcoin {args.network.capitalize()} SegWit Address Generation Details:")
                print("-----------------------------------------")
                print(f"Mnemonic: {address_info['mnemonic']}")
                print(f"Seed (Hex): {address_info['seed_hex']}")
                print(f"XPub: {address_info['xpub']}")
                print(f"Native SegWit Address: {address_info['address']}")
                print(f"Private Key (WIF): {address_info['private_key']}")
                break
            else:
                # Print the address and update the same spot
                sys.stdout.write('\033[2K\033[1G')  # Clear the line and move cursor to the beginning
                sys.stdout.write(f" {'{:,}'.format(hash_count)} Hashes | {address_info['address']}\r")
                sys.stdout.flush()
        elif args.coin == "ethereum":

            if not valid_eth_str(args.search_term):
                print(args.search_term)
                print('Invalid search term.')
                return
            address_info = generate_ethereum_address(mnemonic, passphrase=args.pw)

            if args.match_type == 0:
                if address_info['address'][2:(len(args.search_term) + 2)] == args.search_term:
                    address_matched = True
            else:
                if args.search_term in address_info['address'][2:]:
                #if address_info['address'].startswith(args.search_term):
                    address_matched = True

            if address_matched:
                # Clear the line and print the final details
                sys.stdout.write('\033[2K\033[1G')  # Clear the line and move cursor to the beginning
                print(f"Found vanity seed after {'{:,}'.format(hash_count)} Hashes")
                print("Ethereum Address Generation Details:")
                print("------------------------------------")
                print(f"Mnemonic: {address_info['mnemonic']}")
                print(f"Seed (Hex): {address_info['seed_hex']}")
                print(f"Address: {address_info['address']}")
                print(f"Private Key: {address_info['private_key']}")
                break
            else:
                # Print the address and update the same spot
                sys.stdout.write('\033[2K\033[1G')  # Clear the line and move cursor to the beginning
                sys.stdout.write(f" {'{:,}'.format(hash_count)} Hashes | {address_info['address']}\r")
                sys.stdout.flush()

if __name__ == "__main__":
    main()