#!/usr/bin/env python3
"""FORENSIX Memory Dumper - RAM acquisition and analysis support."""

import os
import time
import subprocess
from datetime import datetime
from typing import Optional, Dict

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="FORENSIX"):
        return logging.getLogger(name)


class MemoryDumper:
    """
    Memory Acquisition Module.
    
    Captures volatile memory (RAM) for forensic analysis.
    Supports Linux memory capture via /dev/mem, /proc/kcore,
    and LiME (Linux Memory Extractor) integration.
    """
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.running = False
        self._progress = 0
    
    def dump_with_lime(self, output_file: str, lime_path: str = "/tmp/lime.ko",
                       format_type: str = "lime") -> Optional[str]:
        """
        Capture memory using LiME kernel module.
        
        Args:
            output_file: Output file for memory dump
            lime_path: Path to LiME kernel module
            format_type: Output format (lime, raw, padded)
        
        Returns:
            Path to memory dump or None
        """
        if not os.path.exists(lime_path):
            self.logger.error(f"LiME module not found: {lime_path}")
            print(f"[!] LiME kernel module required.")
            print(f"    Install: sudo apt install lime-forensics-dkms")
            return None
        
        print(f"\n[*] Starting Memory Acquisition (LiME)")
        print(f"    Output: {output_file}")
        print(f"    Format: {format_type}")
        
        try:
            # Load LiME module
            subprocess.run(
                ["insmod", lime_path, f"path={output_file}", f"format={format_type}"],
                check=True, capture_output=True
            )
            
            # Wait for dump to complete
            print("[*] Capturing memory...")
            while not os.path.exists(output_file):
                time.sleep(1)
            
            # Wait for file to stabilize
            time.sleep(3)
            
            file_size = os.path.getsize(output_file)
            size_gb = file_size / (1024**3)
            
            print(f"[+] Memory dump complete: {size_gb:.2f} GB")
            print(f"    File: {output_file}")
            
            # Remove LiME module
            subprocess.run(["rmmod", "lime"], capture_output=True)
            
            return output_file
            
        except Exception as e:
            self.logger.error(f"LiME dump failed: {e}")
            return None
    
    def dump_proc_kcore(self, output_file: str) -> Optional[str]:
        """
        Capture memory from /proc/kcore (requires root).
        
        Note: /proc/kcore is an ELF image of kernel virtual memory.
        Limited to kernel memory only.
        
        Args:
            output_file: Output file path
        
        Returns:
            Path to memory dump or None
        """
        kcore_path = "/proc/kcore"
        if not os.path.exists(kcore_path):
            self.logger.error("/proc/kcore not available")
            return None
        
        print(f"\n[*] Capturing /proc/kcore...")
        
        try:
            with open(kcore_path, 'rb') as src:
                with open(output_file, 'wb') as dst:
                    while True:
                        chunk = src.read(1048576)  # 1MB
                        if not chunk:
                            break
                        dst.write(chunk)
            
            file_size = os.path.getsize(output_file)
            size_mb = file_size / (1024*1024)
            
            print(f"[+] /proc/kcore dump: {size_mb:.1f} MB")
            print(f"    File: {output_file}")
            return output_file
            
        except Exception as e:
            self.logger.error(f"proc/kcore dump failed: {e}")
            return None
    
    def dump_dev_mem(self, output_file: str, max_size_gb: float = 4) -> Optional[str]:
        """
        Capture physical memory from /dev/mem.
        
        Args:
            output_file: Output file path
            max_size_gb: Maximum dump size in GB
        
        Returns:
            Path to memory dump or None
        """
        mem_path = "/dev/mem"
        if not os.path.exists(mem_path):
            self.logger.error("/dev/mem not available")
            return None
        
        max_bytes = int(max_size_gb * 1024 * 1024 * 1024)
        
        print(f"\n[*] Capturing /dev/mem (max {max_size_gb} GB)...")
        
        try:
            with open(mem_path, 'rb') as src:
                with open(output_file, 'wb') as dst:
                    total = 0
                    while total < max_bytes:
                        chunk = src.read(1048576)  # 1MB
                        if not chunk:
                            break
                        dst.write(chunk)
                        total += len(chunk)
            
            file_size = os.path.getsize(output_file)
            size_gb = file_size / (1024**3)
            
            print(f"[+] /dev/mem dump: {size_gb:.2f} GB")
            print(f"    File: {output_file}")
            return output_file
            
        except Exception as e:
            self.logger.error(f"/dev/mem dump failed: {e}")
            return None
    
    def capture_process_memory(self, pid: int, output_dir: str) -> Dict[str, str]:
        """
        Capture memory of a specific process.
        
        Args:
            pid: Process ID
            output_dir: Output directory for memory files
        
        Returns:
            Dict mapping memory regions to output files
        """
        os.makedirs(output_dir, exist_ok=True)
        
        maps_path = f"/proc/{pid}/maps"
        mem_path = f"/proc/{pid}/mem"
        
        if not os.path.exists(maps_path):
            self.logger.error(f"Process {pid} not found")
            return {}
        
        print(f"\n[*] Capturing process memory (PID: {pid})...")
        captured = {}
        
        try:
            with open(maps_path, 'r') as maps:
                for line in maps:
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    
                    addr_range = parts[0]
                    perms = parts[1]
                    region_name = parts[-1] if len(parts) > 5 else "anonymous"
                    
                    start, end = addr_range.split('-')
                    start_addr = int(start, 16)
                    end_addr = int(end, 16)
                    size = end_addr - start_addr
                    
                    # Safe filename
                    safe_name = region_name.replace('/', '_').replace('\\', '_')
                    output_file = os.path.join(output_dir, f"{pid}_{safe_name}_{start}_{end}.mem")
                    
                    try:
                        with open(mem_path, 'rb') as mem:
                            mem.seek(start_addr)
                            data = mem.read(size)
                            
                        with open(output_file, 'wb') as f:
                            f.write(data)
                        
                        captured[region_name] = output_file
                    except:
                        continue
            
            print(f"[+] Captured {len(captured)} memory regions")
            return captured
            
        except Exception as e:
            self.logger.error(f"Process memory capture failed: {e}")
            return {}
    
    def capture_swap(self, output_file: str) -> Optional[str]:
        """
        Capture swap partition contents.
        
        Args:
            output_file: Output file path
        
        Returns:
            Path to swap dump or None
        """
        print(f"\n[*] Capturing swap partitions...")
        
        try:
            # Find swap partitions
            result = subprocess.run(
                ["swapon", "--show=NAME"],
                capture_output=True, text=True
            )
            
            swap_devices = [line.strip() for line in result.stdout.splitlines()[1:] if line.strip()]
            
            if not swap_devices:
                print("[!] No swap partitions found")
                return None
            
            with open(output_file, 'wb') as out:
                for device in swap_devices:
                    print(f"[*] Dumping {device}...")
                    with open(device, 'rb') as src:
                        while True:
                            chunk = src.read(1048576)
                            if not chunk:
                                break
                            out.write(chunk)
            
            file_size = os.path.getsize(output_file)
            size_gb = file_size / (1024**3)
            
            print(f"[+] Swap dump: {size_gb:.2f} GB")
            print(f"    File: {output_file}")
            return output_file
            
        except Exception as e:
            self.logger.error(f"Swap capture failed: {e}")
            return None
    
    def get_memory_info(self) -> Dict:
        """Get system memory information."""
        info = {
            "total_ram": 0,
            "available_ram": 0,
            "swap_total": 0,
            "swap_free": 0
        }
        
        try:
            # Parse /proc/meminfo
            with open("/proc/meminfo", 'r') as f:
                for line in f:
                    if "MemTotal" in line:
                        info["total_ram"] = int(line.split()[1]) * 1024
                    elif "MemAvailable" in line:
                        info["available_ram"] = int(line.split()[1]) * 1024
                    elif "SwapTotal" in line:
                        info["swap_total"] = int(line.split()[1]) * 1024
                    elif "SwapFree" in line:
                        info["swap_free"] = int(line.split()[1]) * 1024
        except:
            pass
        
        return info
    
    def display_memory_info(self):
        """Display system memory summary."""
        info = self.get_memory_info()
        
        print(f"\n[System Memory]")
        print(f"  RAM Total:     {info['total_ram'] / (1024**3):.2f} GB")
        print(f"  RAM Available: {info['available_ram'] / (1024**3):.2f} GB")
        print(f"  Swap Total:    {info['swap_total'] / (1024**3):.2f} GB")
        print(f"  Swap Free:     {info['swap_free'] / (1024**3):.2f} GB")
    
    def stop(self):
        self.running = False
    
    def get_progress(self) -> int:
        return self._progress
