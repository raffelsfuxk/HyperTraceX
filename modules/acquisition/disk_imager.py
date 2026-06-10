#!/usr/bin/env python3
"""FORENSIX Disk Imager - Raw disk imaging with hash verification."""

import os
import time
import subprocess
import threading
from datetime import datetime
from typing import Optional, Callable

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="FORENSIX"):
        return logging.getLogger(name)


class DiskImager:
    """
    Forensic Disk Imaging Module.
    
    Creates forensic images (raw/E01) of storage devices
    with simultaneous hash calculation for integrity verification.
    """
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.running = False
        self._progress = 0
        self._callback: Optional[Callable] = None
    
    def set_callback(self, callback: Callable):
        self._callback = callback
    
    def create_raw_image(self, source_device: str, destination_file: str,
                         block_size: str = "4M", hash_algorithm: str = "sha256",
                         status_interval: int = 5) -> Optional[str]:
        """
        Create raw forensic image using dd with progress monitoring.
        
        Args:
            source_device: Source device (e.g., /dev/sda1)
            destination_file: Output image file path
            block_size: dd block size
            hash_algorithm: Hash algorithm for verification
            status_interval: Progress update interval in seconds
        
        Returns:
            Hash of created image or None
        """
        if not os.path.exists(source_device):
            self.logger.error(f"Source device not found: {source_device}")
            return None
        
        # Create output directory
        os.makedirs(os.path.dirname(destination_file), exist_ok=True)
        
        # Get source size
        try:
            size_output = subprocess.check_output(
                ["blockdev", "--getsize64", source_device]
            ).decode().strip()
            total_size = int(size_output)
            total_size_gb = total_size / (1024**3)
        except:
            total_size = 0
            total_size_gb = 0
        
        print(f"\n[*] Starting Forensic Imaging")
        print(f"    Source: {source_device}")
        print(f"    Destination: {destination_file}")
        print(f"    Size: {total_size_gb:.2f} GB")
        print(f"    Hash: {hash_algorithm.upper()}")
        print(f"    Block Size: {block_size}\n")
        
        self.running = True
        self._progress = 0
        start_time = time.time()
        
        # Run dd with status=progress
        dd_cmd = [
            "dd",
            f"if={source_device}",
            f"of={destination_file}",
            f"bs={block_size}",
            "status=progress",
            "conv=noerror,sync"
        ]
        
        try:
            proc = subprocess.Popen(
                dd_cmd,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            # Monitor progress from stderr
            def monitor():
                for line in proc.stderr:
                    if not self.running:
                        break
                    if "bytes" in line:
                        print(f"  {line.strip()}", end='\r')
                        # Parse progress
                        try:
                            parts = line.split()
                            bytes_idx = parts.index("bytes")
                            copied = int(parts[bytes_idx - 1])
                            if total_size > 0:
                                self._progress = int((copied / total_size) * 100)
                        except:
                            pass
            
            monitor_thread = threading.Thread(target=monitor, daemon=True)
            monitor_thread.start()
            
            proc.wait()
            monitor_thread.join(timeout=2)
            
            if proc.returncode != 0:
                self.logger.error("dd process failed")
                return None
            
            elapsed = time.time() - start_time
            speed_mbps = (total_size / (1024*1024)) / elapsed if elapsed > 0 else 0
            
            print(f"\n[+] Imaging complete in {elapsed:.1f}s ({speed_mbps:.1f} MB/s)")
            
            # Calculate hash
            print(f"[*] Calculating {hash_algorithm.upper()} hash...")
            hash_value = self._calculate_hash(destination_file, hash_algorithm)
            
            if hash_value:
                print(f"[+] {hash_algorithm.upper()}: {hash_value}")
                
                # Save hash to file
                hash_file = destination_file + f".{hash_algorithm}"
                with open(hash_file, 'w') as f:
                    f.write(f"{hash_value}  {os.path.basename(destination_file)}\n")
                print(f"[+] Hash saved: {hash_file}")
            
            return hash_value
            
        except Exception as e:
            self.logger.error(f"Imaging failed: {e}")
            return None
        finally:
            self.running = False
    
    def create_split_image(self, source_device: str, output_prefix: str,
                           split_size: str = "2G", hash_algorithm: str = "sha256") -> bool:
        """
        Create split forensic image for FAT32 compatibility.
        
        Args:
            source_device: Source device path
            output_prefix: Output file prefix
            split_size: Size of each chunk
            hash_algorithm: Hash algorithm
        
        Returns:
            True if successful
        """
        os.makedirs(os.path.dirname(output_prefix), exist_ok=True)
        
        cmd = [
            "dd",
            f"if={source_device}",
            f"of={output_prefix}.img",
            f"bs=4M",
            f"count={split_size}",
            "status=progress"
        ]
        
        try:
            subprocess.run(cmd, check=True)
            
            # Hash each chunk
            chunk = 1
            while True:
                chunk_file = f"{output_prefix}.img{chunk:03d}" if chunk > 1 else f"{output_prefix}.img"
                if not os.path.exists(chunk_file):
                    break
                
                hash_val = self._calculate_hash(chunk_file, hash_algorithm)
                with open(f"{chunk_file}.{hash_algorithm}", 'w') as f:
                    f.write(f"{hash_val}  {os.path.basename(chunk_file)}\n")
                
                chunk += 1
            
            return True
        except Exception as e:
            self.logger.error(f"Split imaging failed: {e}")
            return False
    
    def verify_image(self, image_file: str, hash_file: str, 
                     hash_algorithm: str = "sha256") -> bool:
        """Verify forensic image integrity."""
        if not os.path.exists(image_file) or not os.path.exists(hash_file):
            return False
        
        print(f"[*] Verifying image integrity...")
        
        try:
            with open(hash_file, 'r') as f:
                expected = f.read().split()[0]
            
            actual = self._calculate_hash(image_file, hash_algorithm)
            
            if actual and actual == expected:
                print(f"[+] VERIFIED: Hash matches")
                return True
            else:
                print(f"[!] FAILED: Hash mismatch!")
                print(f"    Expected: {expected}")
                print(f"    Actual:   {actual}")
                return False
        except Exception as e:
            self.logger.error(f"Verification failed: {e}")
            return False
    
    def _calculate_hash(self, filepath: str, algorithm: str = "sha256") -> Optional[str]:
        """Calculate file hash."""
        import hashlib
        try:
            h = hashlib.new(algorithm)
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception as e:
            self.logger.error(f"Hash error: {e}")
            return None
    
    def stop(self):
        self.running = False
    
    def get_progress(self) -> int:
        return self._progress
