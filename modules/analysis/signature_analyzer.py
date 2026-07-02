#!/usr/bin/env python3
"""HyperTraceX Signature Analyzer - File type detection via magic bytes."""

import os
import json
from typing import Dict, List, Optional, Tuple

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="HyperTraceX"):
        return logging.getLogger(name)


class SignatureAnalyzer:
    """
    File Signature / Magic Bytes Analyzer.
    
    Identifies file types by analyzing magic bytes,
    detects file extension mismatches, and identifies
    potentially disguised files.
    """
    
    # Extended magic bytes database
    MAGIC_SIGNATURES = {
        # Images
        "FFD8FF": {"extension": "jpg", "mime": "image/jpeg", "description": "JPEG Image"},
        "89504E47": {"extension": "png", "mime": "image/png", "description": "PNG Image"},
        "47494638": {"extension": "gif", "mime": "image/gif", "description": "GIF Image"},
        "424D": {"extension": "bmp", "mime": "image/bmp", "description": "BMP Image"},
        "49492A00": {"extension": "tiff", "mime": "image/tiff", "description": "TIFF Image (LE)"},
        "4D4D002A": {"extension": "tiff", "mime": "image/tiff", "description": "TIFF Image (BE)"},
        "00000100": {"extension": "ico", "mime": "image/x-icon", "description": "ICO Icon"},
        "52494646": {"extension": "webp", "mime": "image/webp", "description": "WebP Image"},
        
        # Documents
        "25504446": {"extension": "pdf", "mime": "application/pdf", "description": "PDF Document"},
        "D0CF11E0": {"extension": "doc", "mime": "application/msword", "description": "MS Office Document (OLE)"},
        "504B0304": {"extension": "docx", "mime": "application/zip", "description": "Office Open XML / ZIP"},
        "504B0506": {"extension": "zip", "mime": "application/zip", "description": "ZIP Archive (Empty)"},
        "504B0708": {"extension": "zip", "mime": "application/zip", "description": "ZIP Archive (Spanned)"},
        "52617221": {"extension": "rar", "mime": "application/x-rar", "description": "RAR Archive"},
        "377ABCAF271C": {"extension": "7z", "mime": "application/x-7z-compressed", "description": "7-Zip Archive"},
        "1F8B08": {"extension": "gz", "mime": "application/gzip", "description": "GZip Archive"},
        "425A68": {"extension": "bz2", "mime": "application/x-bzip2", "description": "BZip2 Archive"},
        "FD377A585A00": {"extension": "xz", "mime": "application/x-xz", "description": "XZ Archive"},
        
        # Executables
        "4D5A": {"extension": "exe", "mime": "application/x-msdownload", "description": "Windows Executable"},
        "7F454C46": {"extension": "elf", "mime": "application/x-executable", "description": "ELF Executable"},
        "CAFEBABE": {"extension": "class", "mime": "application/java", "description": "Java Class"},
        "CFFAEDFE": {"extension": "macho", "mime": "application/x-mach-binary", "description": "Mach-O Binary (64-bit)"},
        "FEEDFACE": {"extension": "macho", "mime": "application/x-mach-binary", "description": "Mach-O Binary (32-bit)"},
        
        # Multimedia
        "0000001C66747970": {"extension": "mp4", "mime": "video/mp4", "description": "MP4 Video"},
        "0000002066747970": {"extension": "mp4", "mime": "video/mp4", "description": "MP4 Video"},
        "494433": {"extension": "mp3", "mime": "audio/mpeg", "description": "MP3 Audio (ID3)"},
        "FFFB": {"extension": "mp3", "mime": "audio/mpeg", "description": "MP3 Audio"},
        "FFF3": {"extension": "mp3", "mime": "audio/mpeg", "description": "MP3 Audio"},
        "FFF2": {"extension": "mp3", "mime": "audio/mpeg", "description": "MP3 Audio"},
        "4F676753": {"extension": "ogg", "mime": "audio/ogg", "description": "OGG Audio"},
        "664C6143": {"extension": "flac", "mime": "audio/flac", "description": "FLAC Audio"},
        "52494646": {"extension": "avi", "mime": "video/avi", "description": "AVI Video"},
        
        # Database
        "53514C697465": {"extension": "sqlite", "mime": "application/x-sqlite3", "description": "SQLite Database"},
        "00000001": {"extension": "pcap", "mime": "application/vnd.tcpdump.pcap", "description": "PCAP Capture"},
        "0A0D0D0A": {"extension": "pcapng", "mime": "application/x-pcapng", "description": "PCAPNG Capture"},
        
        # Email
        "46726F6D": {"extension": "eml", "mime": "message/rfc822", "description": "Email (EML)"},
        
        # Other
        "1F9D": {"extension": "z", "mime": "application/x-compress", "description": "Compress Archive"},
        "1FA0": {"extension": "z", "mime": "application/x-compress", "description": "Compress Archive"},
        "213C617263683E": {"extension": "deb", "mime": "application/x-deb", "description": "Debian Package"},
        "454C46": {"extension": "elf", "mime": "application/x-executable", "description": "ELF (short)"},
        "2321": {"extension": "sh", "mime": "text/x-script", "description": "Shell Script"},
        "3C3F786D6C": {"extension": "xml", "mime": "application/xml", "description": "XML Document"},
        "EFBBBF": {"extension": "txt", "mime": "text/plain", "description": "UTF-8 BOM Text"},
        "FFFE": {"extension": "txt", "mime": "text/plain", "description": "UTF-16 LE BOM Text"},
        "FEFF": {"extension": "txt", "mime": "text/plain", "description": "UTF-16 BE BOM Text"},
    }
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.analysis_results: List[Dict] = []
    
    def identify_file(self, filepath: str, read_bytes: int = 16) -> Optional[Dict]:
        """
        Identify file type by magic bytes.
        
        Args:
            filepath: Path to file
            read_bytes: Number of bytes to read for signature
        
        Returns:
            Dict with file type info or None
        """
        if not os.path.exists(filepath):
            return None
        
        try:
            with open(filepath, 'rb') as f:
                header = f.read(read_bytes)
            
            if not header:
                return None
            
            # Convert to hex
            hex_header = header.hex().upper()
            
            # Check against signatures
            for sig, info in sorted(self.MAGIC_SIGNATURES.items(), key=lambda x: len(x[0]), reverse=True):
                if hex_header.startswith(sig):
                    return {
                        "file": filepath,
                        "detected_type": info["extension"],
                        "mime_type": info["mime"],
                        "description": info["description"],
                        "magic_bytes": hex_header[:len(sig)],
                        "current_extension": os.path.splitext(filepath)[1].lower().lstrip('.'),
                        "size": os.path.getsize(filepath)
                    }
            
            return {
                "file": filepath,
                "detected_type": "unknown",
                "mime_type": "application/octet-stream",
                "description": "Unknown file type",
                "magic_bytes": hex_header,
                "current_extension": os.path.splitext(filepath)[1].lower().lstrip('.'),
                "size": os.path.getsize(filepath)
            }
            
        except Exception as e:
            self.logger.error(f"Signature analysis failed for {filepath}: {e}")
            return None
    
    def analyze_directory(self, directory: str, recursive: bool = True) -> List[Dict]:
        """
        Analyze all files in a directory.
        
        Returns:
            List of analysis results
        """
        results = []
        
        if not os.path.exists(directory):
            self.logger.error(f"Directory not found: {directory}")
            return results
        
        print(f"\n[*] Analyzing file signatures...")
        print(f"    Directory: {directory}")
        
        count = 0
        suspicious = 0
        
        try:
            if recursive:
                for dirpath, _, filenames in os.walk(directory):
                    for filename in filenames:
                        filepath = os.path.join(dirpath, filename)
                        result = self.identify_file(filepath)
                        if result:
                            results.append(result)
                            count += 1
                            
                            # Check for extension mismatch
                            if result["current_extension"] and result["detected_type"] != "unknown":
                                if result["current_extension"] != result["detected_type"]:
                                    suspicious += 1
                                    print(f"  [!] Mismatch: {filename} -> .{result['current_extension']} "
                                          f"should be .{result['detected_type']}")
                            
                            if count % 500 == 0:
                                print(f"  Analyzed {count} files...")
            else:
                for filename in os.listdir(directory):
                    filepath = os.path.join(directory, filename)
                    if os.path.isfile(filepath):
                        result = self.identify_file(filepath)
                        if result:
                            results.append(result)
                            count += 1
            
            print(f"\n[+] Analysis complete: {count} files")
            print(f"    Suspicious (mismatched): {suspicious}")
            
        except Exception as e:
            self.logger.error(f"Directory analysis failed: {e}")
        
        self.analysis_results = results
        return results
    
    def find_mismatches(self) -> List[Dict]:
        """Find files where extension doesn't match magic bytes."""
        mismatches = []
        for result in self.analysis_results:
            if result["current_extension"] and result["detected_type"] != "unknown":
                if result["current_extension"] != result["detected_type"]:
                    # Skip known multi-purpose signatures
                    if result["detected_type"] in ["docx", "zip"] and result["current_extension"] in ["docx", "xlsx", "pptx", "zip"]:
                        continue
                    mismatches.append(result)
        return mismatches
    
    def find_by_type(self, file_type: str) -> List[Dict]:
        """Find all files of a specific type."""
        return [r for r in self.analysis_results if r["detected_type"] == file_type]
    
    def find_hidden_files(self) -> List[Dict]:
        """Find potentially hidden files (disguised extensions)."""
        hidden = []
        for result in self.analysis_results:
            # Files with double extensions
            name = os.path.basename(result["file"])
            if name.count('.') >= 2:
                hidden.append(result)
            
            # Executables disguised as something else
            if result["detected_type"] in ["exe", "elf"] and \
               result["current_extension"] not in ["exe", "elf", "dll", "so", ""]:
                hidden.append(result)
        return hidden
    
    def get_statistics(self) -> Dict:
        """Get analysis statistics."""
        if not self.analysis_results:
            return {"total_files": 0}
        
        type_counts = {}
        for r in self.analysis_results:
            ftype = r["detected_type"]
            type_counts[ftype] = type_counts.get(ftype, 0) + 1
        
        total_size = sum(r.get("size", 0) for r in self.analysis_results)
        mismatches = len(self.find_mismatches())
        
        return {
            "total_files": len(self.analysis_results),
            "total_size_mb": round(total_size / (1024*1024), 2),
            "unique_types": len(type_counts),
            "mismatched_extensions": mismatches,
            "type_distribution": dict(sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:10])
        }
    
    def display_results(self, show_all: bool = False):
        """Display analysis results."""
        if not self.analysis_results:
            print("\n[!] No analysis results.\n")
            return
        
        mismatches = self.find_mismatches()
        stats = self.get_statistics()
        
        print(f"\n[File Signature Analysis]")
        print(f"{'='*60}")
        print(f"  Total Files: {stats['total_files']}")
        print(f"  Total Size:  {stats['total_size_mb']} MB")
        print(f"  File Types:  {stats['unique_types']}")
        print(f"  Mismatches:  {len(mismatches)}")
        
        if stats.get("type_distribution"):
            print(f"\n  Top File Types:")
            for ftype, count in stats["type_distribution"].items():
                print(f"    .{ftype:<10} {count}")
        
        if mismatches:
            print(f"\n  [!] Extension Mismatches:")
            for m in mismatches[:10]:
                name = os.path.basename(m["file"])
                print(f"    {name:<40} .{m['current_extension']} -> .{m['detected_type']}")
        
        print(f"{'='*60}\n")
    
    def add_signature(self, magic_hex: str, extension: str, 
                      mime: str = "", description: str = ""):
        """Add custom file signature."""
        self.MAGIC_SIGNATURES[magic_hex.upper()] = {
            "extension": extension.lower(),
            "mime": mime or f"application/x-{extension}",
            "description": description or f"Custom {extension.upper()} file"
        }
    
    def export_signatures(self, output_file: str):
        """Export signature database to JSON."""
        with open(output_file, 'w') as f:
            json.dump(self.MAGIC_SIGNATURES, f, indent=4)
        print(f"[+] Signatures exported: {output_file}")
