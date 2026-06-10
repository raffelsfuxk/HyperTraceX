#!/usr/bin/env python3
"""FORENSIX Partition Scanner - Detect and analyze storage partitions."""

import os
import subprocess
from typing import Dict, List, Optional

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="FORENSIX"):
        return logging.getLogger(name)


class PartitionScanner:
    """
    Storage Partition Scanner & Analyzer.
    
    Detects all connected drives and partitions with
    filesystem identification and mount point analysis.
    """
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self._partitions: List[Dict] = []
    
    def scan_all(self) -> List[Dict]:
        """
        Scan all connected storage devices and partitions.
        
        Returns:
            List of partition dictionaries
        """
        self._partitions.clear()
        
        try:
            output = subprocess.check_output(
                "lsblk -lno NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,LABEL,UUID",
                shell=True
            ).decode()
            
            for line in output.splitlines():
                parts = line.split()
                if len(parts) < 3:
                    continue
                
                name = parts[0]
                size = parts[1]
                dev_type = parts[2]
                
                mountpoint = parts[3] if len(parts) > 3 else ""
                fstype = parts[4] if len(parts) > 4 else ""
                label = parts[5] if len(parts) > 5 else ""
                uuid = parts[6] if len(parts) > 6 else ""
                
                partition = {
                    "device": f"/dev/{name}",
                    "name": name,
                    "size": size,
                    "type": dev_type,
                    "mountpoint": mountpoint,
                    "filesystem": fstype,
                    "label": label,
                    "uuid": uuid
                }
                
                # Add filesystem details
                if fstype:
                    partition["fs_details"] = self._get_fs_details(fstype)
                
                self._partitions.append(partition)
                
        except Exception as e:
            self.logger.error(f"Partition scan failed: {e}")
        
        return self._partitions
    
    def get_by_type(self, fs_type: str) -> List[Dict]:
        """Get partitions by filesystem type (ntfs, ext4, fat32, etc)."""
        return [p for p in self._partitions if p.get("filesystem", "").lower() == fs_type.lower()]
    
    def get_windows_partitions(self) -> List[Dict]:
        """Get all Windows (NTFS/FAT) partitions."""
        windows_fs = ["ntfs", "fuseblk", "vfat", "fat32", "exfat"]
        return [p for p in self._partitions if p.get("filesystem", "").lower() in windows_fs]
    
    def get_linux_partitions(self) -> List[Dict]:
        """Get all Linux (ext/btrfs/xfs) partitions."""
        linux_fs = ["ext2", "ext3", "ext4", "btrfs", "xfs", "jfs"]
        return [p for p in self._partitions if p.get("filesystem", "").lower() in linux_fs]
    
    def get_mac_partitions(self) -> List[Dict]:
        """Get all macOS (HFS/APFS) partitions."""
        mac_fs = ["hfs", "hfsplus", "apfs"]
        return [p for p in self._partitions if p.get("filesystem", "").lower() in mac_fs]
    
    def get_unmounted(self) -> List[Dict]:
        """Get all unmounted partitions (ready for forensic mounting)."""
        return [p for p in self._partitions if not p.get("mountpoint")]
    
    def get_by_label(self, label: str) -> Optional[Dict]:
        """Find partition by label (case-insensitive)."""
        for p in self._partitions:
            if p.get("label", "").lower() == label.lower():
                return p
        return None
    
    def get_by_uuid(self, uuid: str) -> Optional[Dict]:
        """Find partition by UUID."""
        for p in self._partitions:
            if p.get("uuid", "").lower() == uuid.lower():
                return p
        return None
    
    def get_system_partitions(self) -> List[Dict]:
        """Get likely OS system partitions (Windows/System Reserved)."""
        system_labels = ["system reserved", "efi system partition", "recovery", "windows"]
        return [
            p for p in self._partitions
            if p.get("label", "").lower() in system_labels
            or p.get("mountpoint", "") in ["/", "/boot", "/boot/efi"]
        ]
    
    def get_data_partitions(self) -> List[Dict]:
        """Get likely data partitions (non-system)."""
        system = self.get_system_partitions()
        system_devices = [p["device"] for p in system]
        return [p for p in self._partitions if p["device"] not in system_devices]
    
    def get_largest_partitions(self, top_n: int = 5) -> List[Dict]:
        """Get largest partitions by size."""
        def parse_size(size_str: str) -> float:
            try:
                size_str = size_str.upper().strip()
                if 'G' in size_str:
                    return float(size_str.replace('G', ''))
                elif 'T' in size_str:
                    return float(size_str.replace('T', '')) * 1024
                elif 'M' in size_str:
                    return float(size_str.replace('M', '')) / 1024
                return 0
            except:
                return 0
        
        sorted_parts = sorted(
            self._partitions,
            key=lambda p: parse_size(p.get("size", "0")),
            reverse=True
        )
        return sorted_parts[:top_n]
    
    def mount_readonly(self, device: str, mount_point: str) -> bool:
        """
        Mount a partition in read-only mode for forensic acquisition.
        
        Args:
            device: Device path (e.g., /dev/sda1)
            mount_point: Mount directory
        
        Returns:
            True if mount successful
        """
        if not os.path.exists(device):
            self.logger.error(f"Device not found: {device}")
            return False
        
        os.makedirs(mount_point, exist_ok=True)
        
        try:
            # Get filesystem type
            fs_info = None
            for p in self._partitions:
                if p["device"] == device:
                    fs_info = p.get("filesystem", "")
                    break
            
            if not fs_info:
                fs_info = "auto"
            
            # Mount read-only
            mount_cmd = ["mount", "-o", "ro,noexec,nodev,noatime"]
            
            if fs_info == "ntfs" or fs_info == "fuseblk":
                mount_cmd = ["mount", "-t", "ntfs-3g", "-o", "ro,noexec,nodev,noatime,norecover"]
            
            mount_cmd.extend([device, mount_point])
            
            subprocess.run(mount_cmd, check=True, capture_output=True)
            self.logger.info(f"Mounted (read-only): {device} -> {mount_point}")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Mount failed: {e}")
            return False
    
    def unmount(self, mount_point: str) -> bool:
        """Safely unmount a partition."""
        try:
            subprocess.run(["umount", mount_point], check=True, capture_output=True)
            self.logger.info(f"Unmounted: {mount_point}")
            
            # Remove mount directory if empty
            try:
                os.rmdir(mount_point)
            except:
                pass
            
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Unmount failed: {e}")
            return False
    
    def _get_fs_details(self, fstype: str) -> Dict:
        """Get filesystem capabilities."""
        fs_info = {
            "ntfs": {"readable": True, "writable_risky": True, "supports_compression": True, "supports_encryption": True},
            "fuseblk": {"readable": True, "writable_risky": True, "supports_compression": False, "supports_encryption": False},
            "ext4": {"readable": True, "writable_risky": False, "supports_compression": False, "supports_encryption": True},
            "ext3": {"readable": True, "writable_risky": False, "supports_compression": False, "supports_encryption": False},
            "vfat": {"readable": True, "writable_risky": False, "supports_compression": False, "supports_encryption": False},
            "fat32": {"readable": True, "writable_risky": False, "supports_compression": False, "supports_encryption": False},
            "exfat": {"readable": True, "writable_risky": False, "supports_compression": False, "supports_encryption": False},
            "hfsplus": {"readable": True, "writable_risky": True, "supports_compression": True, "supports_encryption": False},
            "apfs": {"readable": True, "writable_risky": True, "supports_compression": False, "supports_encryption": True},
            "btrfs": {"readable": True, "writable_risky": False, "supports_compression": True, "supports_encryption": False},
            "xfs": {"readable": True, "writable_risky": False, "supports_compression": False, "supports_encryption": False},
        }
        return fs_info.get(fstype, {"readable": True, "writable_risky": True, "supports_compression": False, "supports_encryption": False})
    
    def display_partitions(self):
        """Display all detected partitions in formatted table."""
        if not self._partitions:
            print("\n[!] No partitions found. Run scan_all() first.\n")
            return
        
        print(f"\n{'='*85}")
        print(f"{'Device':<14} {'Size':<8} {'Type':<8} {'Filesystem':<12} {'Label':<15} {'Mountpoint'}")
        print(f"{'='*85}")
        
        for p in self._partitions:
            print(f"{p['device']:<14} {p['size']:<8} {p['type']:<8} "
                  f"{p.get('filesystem', 'N/A'):<12} {p.get('label', ''):<15} "
                  f"{p.get('mountpoint', '')}")
        
        print(f"{'='*85}")
        print(f"Total: {len(self._partitions)} partitions\n")
    
    def get_summary(self) -> Dict:
        """Get partition summary statistics."""
        total = len(self._partitions)
        windows = len(self.get_windows_partitions())
        linux = len(self.get_linux_partitions())
        mac = len(self.get_mac_partitions())
        unmounted = len(self.get_unmounted())
        
        return {
            "total_partitions": total,
            "windows_partitions": windows,
            "linux_partitions": linux,
            "mac_partitions": mac,
            "unmounted_partitions": unmounted,
            "devices": [p["device"] for p in self._partitions]
        }
