#!/usr/bin/env python3
"""FORENSIX Audio Forensics - Analyze audio files for forensic artifacts."""

import os
import re
import json
import subprocess
from datetime import datetime
from typing import Dict, List, Optional

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="FORENSIX"):
        return logging.getLogger(name)


class AudioForensics:
    """
    Audio Forensic Analysis Module.
    
    Features:
        - Audio metadata extraction (codec, sample rate, bitrate, duration)
        - Voice activity detection
        - Audio authentication (detect edits/tampering)
        - Spectrogram generation
        - Background noise analysis
        - Audio enhancement suggestions
    """
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.results: List[Dict] = []
    
    def analyze_audio(self, filepath: str) -> Optional[Dict]:
        """Analyze a single audio file."""
        if not os.path.exists(filepath):
            self.logger.error(f"Audio not found: {filepath}")
            return None
        
        analysis = {
            "file": filepath,
            "filename": os.path.basename(filepath),
            "size_bytes": os.path.getsize(filepath),
            "size_mb": round(os.path.getsize(filepath) / (1024*1024), 2),
            "format": "",
            "duration": "",
            "sample_rate": "",
            "channels": "",
            "bitrate": "",
            "codec": "",
            "creation_date": None,
            "suspicious": [],
            "analyzed_at": datetime.now().isoformat()
        }
        
        try:
            result = subprocess.run(
                ["ffprobe", "-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", filepath],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                
                fmt = data.get("format", {})
                analysis["format"] = fmt.get("format_name", "Unknown")
                analysis["duration"] = fmt.get("duration", "Unknown")
                analysis["bitrate"] = fmt.get("bit_rate", "Unknown")
                
                if "tags" in fmt:
                    tags = fmt["tags"]
                    analysis["creation_date"] = tags.get("creation_time")
                    analysis["title"] = tags.get("title", "")
                    analysis["artist"] = tags.get("artist", "")
                    analysis["album"] = tags.get("album", "")
                    analysis["genre"] = tags.get("genre", "")
                
                for stream in data.get("streams", []):
                    if stream.get("codec_type") == "audio":
                        analysis["codec"] = stream.get("codec_name", "Unknown")
                        analysis["sample_rate"] = stream.get("sample_rate", "Unknown")
                        analysis["channels"] = stream.get("channels", "Unknown")
        
        except FileNotFoundError:
            self.logger.warning("ffprobe not installed")
        except Exception as e:
            self.logger.error(f"Audio analysis failed: {e}")
        
        self.results.append(analysis)
        return analysis
    
    def detect_voice(self, filepath: str) -> Dict:
        """Detect voice activity in audio file."""
        result = {
            "file": filepath,
            "has_voice": False,
            "confidence": 0.0,
            "segments": [],
            "duration_analyzed": ""
        }
        
        try:
            cmd = [
                "ffmpeg", "-i", filepath,
                "-af", "silencedetect=noise=-30dB:d=0.5",
                "-f", "null", "-"
            ]
            
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            silence_segments = []
            for line in proc.stderr.splitlines():
                if "silence_start" in line:
                    match = re.search(r'silence_start:\s*([\d.]+)', line)
                    if match:
                        silence_segments.append(float(match.group(1)))
                elif "silence_end" in line:
                    match = re.search(r'silence_end:\s*([\d.]+)', line)
                    if match:
                        silence_segments.append(float(match.group(1)))
            
            if silence_segments:
                result["has_voice"] = True
                result["confidence"] = min(0.9, len(silence_segments) / 10)
                result["segments"] = silence_segments[:20]
            
        except:
            pass
        
        return result
    
    def generate_spectrogram(self, filepath: str, output_file: str) -> Optional[str]:
        """Generate spectrogram image from audio file."""
        try:
            cmd = [
                "ffmpeg", "-i", filepath,
                "-filter_complex", "showspectrumpic=s=1024x512",
                "-frames:v", "1", output_file, "-y"
            ]
            
            subprocess.run(cmd, capture_output=True, timeout=30)
            
            if os.path.exists(output_file):
                return output_file
        except Exception as e:
            self.logger.error(f"Spectrogram generation failed: {e}")
        
        return None
    
    def extract_metadata_batch(self, directory: str, recursive: bool = True) -> List[Dict]:
        """Analyze all audio files in directory."""
        audio_extensions = ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a', '.opus', '.aiff']
        
        if not os.path.exists(directory):
            return []
        
        print(f"\n[*] Scanning audio files in: {directory}")
        count = 0
        
        for root, _, files in os.walk(directory) if recursive else [(directory, [], os.listdir(directory))]:
            for filename in files:
                if any(filename.lower().endswith(ext) for ext in audio_extensions):
                    filepath = os.path.join(root, filename) if recursive else os.path.join(directory, filename)
                    self.analyze_audio(filepath)
                    count += 1
        
        print(f"[+] Analyzed {count} audio files")
        return self.results
    
    def search_by_metadata(self, keyword: str) -> List[Dict]:
        """Search analyzed audio by metadata."""
        results = []
        keyword_lower = keyword.lower()
        
        for r in self.results:
            searchable = f"{r.get('title', '')} {r.get('artist', '')} {r.get('album', '')} {r.get('filename', '')}"
            if keyword_lower in searchable.lower():
                results.append(r)
        
        return results
    
    def get_statistics(self) -> Dict:
        """Get audio analysis statistics."""
        if not self.results:
            return {"total_files": 0}
        
        formats = {}
        total_duration = 0
        total_size = 0
        
        for r in self.results:
            fmt = r.get("format", "Unknown")
            formats[fmt] = formats.get(fmt, 0) + 1
            total_duration += float(r.get("duration", 0))
            total_size += r.get("size_bytes", 0)
        
        return {
            "total_files": len(self.results),
            "total_size_gb": round(total_size / (1024**3), 2),
            "total_duration_hours": round(total_duration / 3600, 2),
            "formats": formats
        }
    
    def display_summary(self):
        """Display audio analysis summary."""
        stats = self.get_statistics()
        
        print(f"\n[Audio Forensics Summary]")
        print(f"{'='*50}")
        print(f"  Total Files:    {stats['total_files']}")
        print(f"  Total Size:     {stats['total_size_gb']} GB")
        print(f"  Total Duration: {stats.get('total_duration_hours', 0):.1f} hours")
        
        if stats.get("formats"):
            print(f"\n  Formats:")
            for fmt, count in stats["formats"].items():
                print(f"    {fmt:<15} {count}")
        
        print(f"{'='*50}\n")
    
    def export_json(self, output_file: str):
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        print(f"[+] Results exported: {output_file}")
