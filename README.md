# Vanity Crypto Address Generator

A Python-based tool for generating vanity cryptocurrency addresses for Bitcoin (SegWit) and Ethereum. This tool allows you to create wallet addresses containing specific characters or patterns, with detailed analysis of the search complexity.

## Features

- Supports both Bitcoin (SegWit) and Ethereum address generation
- Provides search complexity analysis and time estimates
- Flexible search options (prefix or contains)
- Support for custom BIP39 mnemonic word counts (12, 15, 18, 21, 24 words)
- Optional passphrase support for additional security
- Compatible with Bitcoin mainnet and testnet

## Prerequisites

```bash
pip install bip_utils
```

## Usage

Basic command structure:
```bash
python vanity-genesis.py <search_term> [options]
```

### Options

- `--coin`: Choose cryptocurrency type (bitcoin/ethereum, default: bitcoin)
- `--network`: Select network type (mainnet/testnet, default: mainnet)
- `--wordcount`: Number of words in mnemonic (12/15/18/21/24, default: 12)
- `--match_type`: Search type (0: prefix match, 1: contains match, default: 1)
- `--pw`: Optional passphrase for additional security (default: empty)

### Examples

1. Generate a Bitcoin address starting with "abc":
```bash
python vanity-genesis.py abc --coin bitcoin --match_type 0
```

2. Generate an Ethereum address containing "dead":
```bash
python vanity-genesis.py dead --coin ethereum
```

3. Generate a Bitcoin testnet address with 24-word mnemonic:
```bash
python vanity-genesis.py abc --network testnet --wordcount 24
```

### Output Example

The tool first provides an analysis of the search complexity:
```
Vanity Address Analysis for 'abc' (bitcoin)
--------------------------------------------------
Single address generation time: 0.0123 seconds
Search space size: 32,768 possibilities
Average attempts needed: 16,384

Estimated time to find match:
  Seconds: 201.52
  Minutes: 3.36
  Hours: 0.06
  Days: 0.002
```

When a matching address is found, it displays:
```
Found vanity seed after 15,483 Hashes
Bitcoin Mainnet SegWit Address Generation Details:
-----------------------------------------
Mnemonic: word1 word2 ... word12
Seed (Hex): 1234...
XPub: xpub...
Native SegWit Address: bc1...
Private Key (WIF): L...
```

## Important Notes

1. **Search Complexity**: The time to find a match increases exponentially with the length of your search term. The tool provides estimates before starting the search.

2. **Character Sets**:
   - Bitcoin SegWit addresses allow: 023456789acdefghjklmnpqrstuvwxyz
   - Ethereum addresses allow: 0-9 and a-f (hex)

3. **Security**: Always verify the generated addresses and keep your mnemonics and private keys secure.

## License

This project is open source and available under the MIT License.

## Security Warning

⚠️ Never share your private keys or mnemonics with anyone. Always verify addresses before use. This tool is for educational and testing purposes only. Use at your own risk.
