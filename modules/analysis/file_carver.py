#!/usr/bin/env python3
"""HyperTraceX File Carver - Recover deleted files using header/footer signatures."""

import os
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="HyperTraceX"):
        return logging.getLogger(name)


class FileCarver:
    """
    File Carving Engine.
    
    Recovers deleted files from raw disk images or unallocated space
    using file signature (magic bytes) detection.
    """
    
    # Common file signatures (magic bytes)
    FILE_SIGNATURES = {
        "jpg": {
            "headers": [b"\xFF\xD8\xFF"],
            "footers": [b"\xFF\xD9"],
            "description": "JPEG Image"
        },
        "png": {
            "headers": [b"\x89PNG\r\n\x1a\n"],
            "footers": [b"IEND\xaeB`\x82"],
            "description": "PNG Image"
        },
        "gif": {
            "headers": [b"GIF87a", b"GIF89a"],
            "footers": [b"\x00\x3B"],
            "description": "GIF Image"
        },
        "pdf": {
            "headers": [b"%PDF"],
            "footers": [b"%%EOF", b"%%EOF\r\n", b"%%EOF\n"],
            "description": "PDF Document"
        },
        "docx": {
            "headers": [b"PK\x03\x04"],
            "footers": [b"PK\x05\x06"],
            "description": "Office Document (DOCX/XLSX/PPTX)"
        },
        "zip": {
            "headers": [b"PK\x03\x04"],
            "footers": [],
            "description": "ZIP Archive"
        },
        "rar": {
            "headers": [b"Rar!\x1a\x07"],
            "footers": [],
            "description": "RAR Archive"
        },
        "7z": {
            "headers": [b"7z\xbc\xaf'\x1c"],
            "footers": [],
            "description": "7-Zip Archive"
        },
        "exe": {
            "headers": [b"MZ"],
            "footers": [],
            "description": "Windows Executable"
        },
        "elf": {
            "headers": [b"\x7fELF"],
            "footers": [],
            "description": "Linux Executable"
        },
        "sqlite": {
            "headers": [b"SQLite format 3\x00"],
            "footers": [],
            "description": "SQLite Database"
        },
        "mp4": {
            "headers": [b"\x00\x00\x00\x18ftypmp42", b"\x00\x00\x00\x20ftypmp42"],
            "footers": [],
            "description": "MP4 Video"
        },
        "mp3": {
            "headers": [b"\xFF\xFB", b"\xFF\xF3", b"\xFF\xF2", b"ID3"],
            "footers": [],
            "description": "MP3 Audio"
        },
        "wav": {
            "headers": [b"RIFF"],
            "footers": [],
            "description": "WAV Audio"
        },
        "bmp": {
            "headers": [b"BM"],
            "footers": [],
            "description": "BMP Image"
        },
        "tiff": {
            "headers": [b"II*\x00", b"MM\x00*"],
            "footers": [],
            "description": "TIFF Image"
        }
    }
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.carved_files: List[Dict] = []
        self._progress = 0
    
    def carve_from_file(self, source_file: str, output_dir: str,
                        file_types: Optional[List[str]] = None,
                        min_size: int = 1024) -> List[Dict]:
        """
        Carve files from a forensic image or disk.
        
        Args:
            source_file: Path to source image/disk
            output_dir: Output directory for carved files
            file_types: List of file extensions to carve (None = all)
            min_size: Minimum carved file size in bytes
        
        Returns:
            List of carved file information
        """
        if not os.path.exists(source_file):
            self.logger.error(f"Source file not found: {source_file}")
            return []
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Filter signatures
        signatures = {}
        if file_types:
            for ext in file_types:
                ext_lower = ext.lower().lstrip('.')
                if ext_lower in self.FILE_SIGNATURES:
                    signatures[ext_lower] = self.FILE_SIGNATURES[ext_lower]
        else:
            signatures = self.FILE_SIGNATURES
        
        if not signatures:
            self.logger.error("No valid file types specified")
            return []
        
        print(f"\n[*] Starting File Carving")
        print(f"    Source: {source_file}")
        print(f"    Output: {output_dir}")
        print(f"    Types: {', '.join(signatures.keys()) if file_types else 'ALL'}")
        print(f"    Min Size: {min_size} bytes\n")
        
        self.carved_files.clear()
        source_size = os.path.getsize(source_file)
        carved_count = 0
        
        try:
            with open(source_file, 'rb') as src:
                buffer = bytearray()
                chunk_size = 1048576  # 1MB
                offset = 0
                
                while True:
                    chunk = src.read(chunk_size)
                    if not chunk:
                        break
                    
                    buffer.extend(chunk)
                    
                    # Search for headers in buffer
                    for ext, sig_info in signatures.items():
                        for header in sig_info["headers"]:
                            pos = buffer.find(header)
                            while pos != -1:
                                # Try to find footer
                                footer_pos = -1
                                carved_data = None
                                
                                if sig_info["footers"]:
                                    # Search for footer after header
                                    for footer in sig_info["footers"]:
                                        search_start = pos + len(header)
                                        fp = buffer.find(footer, search_start)
                                        if fp != -1:
                                            footer_pos = fp + len(footer)
                                            break
                                    
                                    if footer_pos > 0:
                                        carved_data = bytes(buffer[pos:footer_pos])
                                    else:
                                        # No footer found, take until next header or max
                                        end = min(pos + 10485760, len(buffer))  # 10MB max without footer
                                        carved_data = bytes(buffer[pos:end])
                                else:
                                    # No footer defined, take fixed chunk
                                    end = min(pos + 10485760, len(buffer))
                                    carved_data = bytes(buffer[pos:end])
                                
                                if carved_data and len(carved_data) >= min_size:
                                    # Generate output filename
                                    file_hash = hashlib.md5(carved_data[:512]).hexdigest()[:12]
                                    output_file = os.path.join(
                                        output_dir,
                                        f"carved_{offset+pos}_{file_hash}.{ext}"
                                    )
                                    
                                    with open(output_file, 'wb') as out:
                                        out.write(carved_data)
                                    
                                    actual_size = os.path.getsize(output_file)
                                    
                                    file_info = {
                                        "original_offset": offset + pos,
                                        "output_file": output_file,
                                        "file_type": ext,
                                        "size": actual_size,
                                        "header": header.hex(),
                                        "carved_at": datetime.now().isoformat()
                                    }
                                    
                                    self.carved_files.append(file_info)
                                    carved_count += 1
                                    
                                    print(f"  [{carved_count}] {ext.upper():<8} "
                                          f"Offset: {offset+pos:<12} "
                                          f"Size: {actual_size:<10} "
                                          f"{os.path.basename(output_file)}")
                                
                                # Continue search after this match
                                pos = buffer.find(header, pos + 1)
                    
                    # Trim buffer to prevent memory overflow
                    if len(buffer) > chunk_size * 3:
                        buffer = buffer[-chunk_size:]
                    
                    offset += len(chunk)
                    self._progress = int((offset / source_size) * 100) if source_size > 0 else 0
            
            print(f"\n[+] Carving complete: {carved_count} files recovered")
            return self.carved_files
            
        except Exception as e:
            self.logger.error(f"File carving failed: {e}")
            return []
    
    def carve_from_bytes(self, data: bytes, output_dir: str,
                         file_types: Optional[List[str]] = None) -> List[Dict]:
        """Carve files from raw bytes (for memory dump analysis)."""
        # Write to temp file and carve
        import tempfile
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.write(data)
        tmp.close()
        
        results = self.carve_from_file(tmp.name, output_dir, file_types)
        os.unlink(tmp.name)
        return results
    
    def add_signature(self, extension: str, headers: List[bytes],
                      footers: List[bytes] = None, description: str = ""):
        """Add custom file signature for carving."""
        self.FILE_SIGNATURES[extension.lower()] = {
            "headers": headers,
            "footers": footers or [],
            "description": description or f"Custom {extension.upper()} file"
        }
    
    def list_signatures(self) -> Dict[str, str]:
        """List all supported file signatures."""
        return {ext: info["description"] for ext, info in self.FILE_SIGNATURES.items()}
    
    def get_statistics(self) -> Dict:
        """Get carving session statistics."""
        total_size = sum(f["size"] for f in self.carved_files)
        type_counts = {}
        for f in self.carved_files:
            ext = f["file_type"]
            type_counts[ext] = type_counts.get(ext, 0) + 1
        
        return {
            "total_files": len(self.carved_files),
            "total_size": total_size,
            "total_size_mb": round(total_size / (1024*1024), 2),
            "file_types": type_counts
        }
    
    def get_progress(self) -> int:
        return self._progress
    
    def display_signatures(self):
        """Display available file signatures."""
        print(f"\n[Available File Signatures]")
        print(f"{'='*50}")
        for ext, info in sorted(self.FILE_SIGNATURES.items()):
            print(f"  .{ext:<10} {info['description']}")
        print(f"{'='*50}\n")
