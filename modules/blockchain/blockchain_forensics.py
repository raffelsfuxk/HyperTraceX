#!/usr/bin/env python3
"""HyperTraceX Blockchain Forensics - Cryptocurrency wallet and transaction analysis."""

import os
import re
import json
from datetime import datetime
from typing import Dict, List, Optional

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="HyperTraceX"):
        return logging.getLogger(name)


class BlockchainForensics:
    """
    Cryptocurrency & Blockchain Forensic Analysis Module.
    
    Features:
        - Cryptocurrency wallet detection
        - Wallet address extraction
        - Exchange token/API key detection
        - Mining malware detection
        - Blockchain address extraction from text
        - Crypto transaction history
    """
    
    # Cryptocurrency address patterns
    CRYPTO_PATTERNS = {
        "bitcoin": {
            "legacy": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            "bech32": r'\bbc1[a-z0-9]{39,59}\b',
            "description": "Bitcoin (BTC)"
        },
        "ethereum": {
            "address": r'\b0x[a-fA-F0-9]{40}\b',
            "description": "Ethereum (ETH)"
        },
        "litecoin": {
            "legacy": r'\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b',
            "description": "Litecoin (LTC)"
        },
        "dogecoin": {
            "address": r'\bD{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}\b',
            "description": "Dogecoin (DOGE)"
        },
        "monero": {
            "address": r'\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b',
            "description": "Monero (XMR)"
        },
        "ripple": {
            "address": r'\br[0-9a-zA-Z]{24,34}\b',
            "description": "Ripple (XRP)"
        }
    }
    
    # Wallet file indicators
    WALLET_INDICATORS = {
        "bitcoin_core": ["wallet.dat", "bitcoin.conf"],
        "electrum": ["electrum", "default_wallet"],
        "ethereum": ["keystore", "UTC--"],
        "metamask": ["metamask", "MetaMask"],
        "trust_wallet": ["trustwallet", "Trust Wallet"],
        "exodus": ["exodus.wallet", "Exodus"],
        "ledger": ["ledger live", "Ledger Live"],
        "trezor": ["trezor suite", "Trezor Suite"]
    }
    
    # Exchange domain patterns
    EXCHANGE_PATTERNS = [
        "binance.com", "coinbase.com", "kraken.com", "gemini.com",
        "bitfinex.com", "huobi.com", "okx.com", "bybit.com",
        "kucoin.com", "gate.io", "crypto.com", "ftx.com"
    ]
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.results: Dict[str, List] = {
            "wallets_found": [],
            "addresses_extracted": [],
            "exchange_tokens": [],
            "mining_indicators": [],
            "wallet_files": []
        }
    
    def scan_directory(self, directory: str, recursive: bool = True) -> Dict:
        """
        Scan directory for cryptocurrency artifacts.
        
        Args:
            directory: Directory to scan
            recursive: Scan subdirectories
        
        Returns:
            Dict with found artifacts
        """
        if not os.path.exists(directory):
            self.logger.error(f"Directory not found: {directory}")
            return self.results
        
        print(f"\n[*] Scanning for blockchain artifacts in: {directory}")
        
        # Find wallet files
        self._find_wallet_files(directory, recursive)
        
        # Scan text files for addresses
        self._scan_for_addresses(directory, recursive)
        
        # Scan for exchange tokens
        self._scan_for_exchange_tokens(directory, recursive)
        
        return self.results
    
    def _find_wallet_files(self, directory: str, recursive: bool):
        """Find cryptocurrency wallet files."""
        found = []
        
        try:
            if recursive:
                for root, _, files in os.walk(directory):
                    for filename in files:
                        filepath = os.path.join(root, filename)
                        
                        for wallet_type, indicators in self.WALLET_INDICATORS.items():
                            for indicator in indicators:
                                if indicator.lower() in filepath.lower():
                                    found.append({
                                        "file": filepath,
                                        "wallet_type": wallet_type,
                                        "size": os.path.getsize(filepath)
                                    })
            else:
                for filename in os.listdir(directory):
                    filepath = os.path.join(directory, filename)
                    if os.path.isfile(filepath):
                        for wallet_type, indicators in self.WALLET_INDICATORS.items():
                            for indicator in indicators:
                                if indicator.lower() in filename.lower():
                                    found.append({
                                        "file": filepath,
                                        "wallet_type": wallet_type,
                                        "size": os.path.getsize(filepath)
                                    })
        except Exception as e:
            self.logger.error(f"Wallet scan error: {e}")
        
        self.results["wallet_files"] = found
        print(f"  [*] Found {len(found)} potential wallet files")
    
    def _scan_for_addresses(self, directory: str, recursive: bool):
        """Scan text files for cryptocurrency addresses."""
        addresses = []
        scanned_files = 0
        
        text_extensions = ['.txt', '.csv', '.json', '.xml', '.log', '.py', '.js', '.html', '.md']
        
        try:
            if recursive:
                for root, _, files in os.walk(directory):
                    for filename in files:
                        if any(filename.lower().endswith(ext) for ext in text_extensions):
                            filepath = os.path.join(root, filename)
                            addresses.extend(self._extract_addresses_from_file(filepath))
                            scanned_files += 1
            else:
                for filename in os.listdir(directory):
                    if any(filename.lower().endswith(ext) for ext in text_extensions):
                        filepath = os.path.join(directory, filename)
                        addresses.extend(self._extract_addresses_from_file(filepath))
                        scanned_files += 1
        except Exception as e:
            self.logger.error(f"Address scan error: {e}")
        
        self.results["addresses_extracted"] = addresses
        print(f"  [*] Extracted {len(addresses)} addresses from {scanned_files} files")
    
    def _extract_addresses_from_file(self, filepath: str) -> List[Dict]:
        """Extract crypto addresses from a single file."""
        found = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for crypto, patterns in self.CRYPTO_PATTERNS.items():
                for pattern_name, regex in patterns.items():
                    if pattern_name == "description":
                        continue
                    
                    matches = re.findall(regex, content)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        
                        found.append({
                            "file": filepath,
                            "cryptocurrency": crypto,
                            "address": match,
                            "type": pattern_name
                        })
        except:
            pass
        
        return found
    
    def _scan_for_exchange_tokens(self, directory: str, recursive: bool):
        """Scan for exchange API tokens and keys."""
        tokens = []
        
        token_patterns = [
            r'(?:api[_-]?key|apikey|api_secret|secret_key)[\s:=]+["\']?([A-Za-z0-9+/=]{20,})["\']?',
            r'(?:binance|coinbase|kraken)[\s:=]+["\']?([A-Za-z0-9]{20,})["\']?',
        ]
        
        try:
            for root, _, files in os.walk(directory) if recursive else [(directory, [], os.listdir(directory))]:
                for filename in files:
                    filepath = os.path.join(root, filename) if recursive else os.path.join(directory, filename)
                    
                    if not os.path.isfile(filepath):
                        continue
                    
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()[:10000]
                        
                        for pattern in token_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            for match in matches:
                                tokens.append({
                                    "file": filepath,
                                    "token": match[:30] + "..." if len(match) > 30 else match,
                                    "pattern": pattern
                                })
                    except:
                        pass
        except:
            pass
        
        self.results["exchange_tokens"] = tokens[:50]
        print(f"  [*] Found {len(tokens)} potential exchange tokens")
    
    def detect_mining_activity(self, directory: str) -> List[Dict]:
        """Detect cryptocurrency mining indicators."""
        indicators = []
        
        mining_keywords = [
            "miner", "mining", "stratum", "nicehash", "cryptonight",
            "xmrig", "ccminer", "ethminer", "cgminer", "bfgminer",
            "cryptominer", "coinminer", "gpuminer"
        ]
        
        mining_ports = [3333, 4444, 5555, 8080, 14444, 33333]
        
        try:
            for root, _, files in os.walk(directory):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    
                    if not os.path.isfile(filepath):
                        continue
                    
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()[:5000].lower()
                        
                        for keyword in mining_keywords:
                            if keyword in content:
                                indicators.append({
                                    "file": filepath,
                                    "indicator": keyword,
                                    "type": "keyword"
                                })
                        
                        for port in mining_ports:
                            if f":{port}" in content or f"port={port}" in content:
                                indicators.append({
                                    "file": filepath,
                                    "indicator": f"Port {port}",
                                    "type": "mining_port"
                                })
                    except:
                        pass
        except:
            pass
        
        self.results["mining_indicators"] = indicators
        return indicators
    
    def extract_from_browser_data(self, browser_data: Dict) -> List[Dict]:
        """Extract crypto-related data from browser artifacts."""
        crypto_urls = []
        
        crypto_domains = [
            "blockchain.com", "etherscan.io", "blockchair.com",
            "coinmarketcap.com", "coingecko.com", "defi",
            "uniswap", "pancakeswap", "sushiswap", "metamask.io"
        ]
        
        for entry in browser_data:
            url = entry.get("url", "").lower()
            
            for domain in crypto_domains:
                if domain in url:
                    crypto_urls.append({
                        "url": url,
                        "title": entry.get("title", ""),
                        "last_visit": entry.get("last_visit", ""),
                        "platform": domain
                    })
        
        return crypto_urls
    
    def get_statistics(self) -> Dict:
        """Get blockchain analysis statistics."""
        return {
            "wallet_files": len(self.results.get("wallet_files", [])),
            "addresses": len(self.results.get("addresses_extracted", [])),
            "exchange_tokens": len(self.results.get("exchange_tokens", [])),
            "mining_indicators": len(self.results.get("mining_indicators", []))
        }
    
    def display_summary(self):
        """Display blockchain analysis summary."""
        stats = self.get_statistics()
        
        print(f"\n[Blockchain Forensics Summary]")
        print(f"{'='*50}")
        print(f"  Wallet Files:       {stats['wallet_files']}")
        print(f"  Crypto Addresses:   {stats['addresses']}")
        print(f"  Exchange Tokens:    {stats['exchange_tokens']}")
        print(f"  Mining Indicators:  {stats['mining_indicators']}")
        print(f"{'='*50}\n")
        
        # Show top addresses
        addresses = self.results.get("addresses_extracted", [])
        if addresses:
            print(f"[Top Crypto Addresses Found]")
            for addr in addresses[:10]:
                print(f"  [{addr.get('cryptocurrency', '?').upper()}] {addr.get('address', '')[:40]}")
            print()
    
    def export_json(self, output_file: str):
        """Export results to JSON."""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        print(f"[+] Blockchain analysis exported: {output_file}")
