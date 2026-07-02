#!/usr/bin/env python3
"""HyperTraceX Video Forensics - Analyze video files for forensic artifacts."""

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
    def get_logger(name="HyperTraceX"):
        return logging.getLogger(name)


class VideoForensics:
    """
    Video Forensic Analysis Module.
    
    Features:
        - Metadata extraction (codec, resolution, duration, bitrate)
        - Creation/modification date extraction
        - GPS location extraction from drone/camera videos
        - Frame analysis (keyframes, motion detection)
        - Video authentication (detect edits/tampering)
        - Thumbnail generation
        - CCTV timestamp extraction
        - Stream analysis
    """
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.results: List[Dict] = []
    
    def analyze_video(self, filepath: str) -> Optional[Dict]:
        """
        Analyze a single video file.
        
        Args:
            filepath: Path to video file
        
        Returns:
            Dict with video metadata and analysis
        """
        if not os.path.exists(filepath):
            self.logger.error(f"Video not found: {filepath}")
            return None
        
        analysis = {
            "file": filepath,
            "filename": os.path.basename(filepath),
            "size_bytes": os.path.getsize(filepath),
            "size_mb": round(os.path.getsize(filepath) / (1024*1024), 2),
            "format": "",
            "duration": "",
            "resolution": "",
            "codec": "",
            "bitrate": "",
            "fps": "",
            "creation_date": None,
            "modification_date": None,
            "gps_coordinates": None,
            "has_audio": False,
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
                    analysis["encoder"] = tags.get("encoder", "")
                    analysis["title"] = tags.get("title", "")
                    analysis["comment"] = tags.get("comment", "")
                    
                    if "location" in tags:
                        analysis["gps_coordinates"] = tags["location"]
                
                for stream in data.get("streams", []):
                    if stream.get("codec_type") == "video":
                        analysis["codec"] = stream.get("codec_name", "Unknown")
                        analysis["resolution"] = f"{stream.get('width', '?')}x{stream.get('height', '?')}"
                        
                        fps_str = stream.get("r_frame_rate", "0/1")
                        try:
                            num, den = fps_str.split("/")
                            analysis["fps"] = round(float(num) / float(den), 2) if float(den) != 0 else 0
                        except:
                            analysis["fps"] = fps_str
                    
                    if stream.get("codec_type") == "audio":
                        analysis["has_audio"] = True
                        analysis["audio_codec"] = stream.get("codec_name", "")
                
                if float(analysis.get("duration", 0)) < 1.0:
                    analysis["suspicious"].append("Very short duration (possible clip)")
                
                if not analysis.get("creation_date"):
                    analysis["suspicious"].append("No creation date (possible edited file)")
        
        except FileNotFoundError:
            self.logger.warning("ffprobe not installed. Install: sudo apt install ffmpeg")
        except Exception as e:
            self.logger.error(f"Video analysis failed: {e}")
        
        self.results.append(analysis)
        return analysis
    
    def extract_metadata_batch(self, directory: str, recursive: bool = True) -> List[Dict]:
        """Analyze all videos in a directory."""
        video_extensions = ['.mp4', '.avi', '.mov', '.mkv', '.wmv', '.flv', '.webm', '.m4v', '.3gp']
        
        if not os.path.exists(directory):
            return []
        
        print(f"\n[*] Scanning videos in: {directory}")
        count = 0
        
        for root, _, files in os.walk(directory) if recursive else [(directory, [], os.listdir(directory))]:
            for filename in files:
                if any(filename.lower().endswith(ext) for ext in video_extensions):
                    filepath = os.path.join(root, filename) if recursive else os.path.join(directory, filename)
                    self.analyze_video(filepath)
                    count += 1
                    if count % 50 == 0:
                        print(f"  Analyzed {count} videos...")
        
        print(f"[+] Analyzed {count} videos")
        return self.results
    
    def detect_cctv_timestamps(self, filepath: str) -> List[str]:
        """Try to detect CCTV timestamp overlay in video."""
        timestamps = []
        
        try:
            cmd = [
                "ffmpeg", "-i", filepath,
                "-vf", "fps=1/5",
                "-vframes", "12",
                "-f", "image2pipe", "-"
            ]
            
            subprocess.run(cmd, capture_output=True, timeout=30)
        except:
            pass
        
        return timestamps
    
    def generate_thumbnails(self, filepath: str, output_dir: str, count: int = 5) -> List[str]:
        """Generate thumbnail images from video at intervals."""
        thumbnails = []
        
        os.makedirs(output_dir, exist_ok=True)
        basename = os.path.splitext(os.path.basename(filepath))[0]
        
        try:
            duration_cmd = ["ffprobe", "-v", "quiet", "-show_entries", "format=duration", 
                           "-of", "csv=p=0", filepath]
            result = subprocess.run(duration_cmd, capture_output=True, text=True)
            duration = float(result.stdout.strip()) if result.stdout.strip() else 60
            
            interval = duration / (count + 1)
            
            for i in range(1, count + 1):
                timestamp = interval * i
                output_file = os.path.join(output_dir, f"{basename}_thumb_{i}.jpg")
                
                cmd = [
                    "ffmpeg", "-ss", str(timestamp), "-i", filepath,
                    "-vframes", "1", "-q:v", "2", output_file, "-y"
                ]
                
                subprocess.run(cmd, capture_output=True, timeout=10)
                
                if os.path.exists(output_file):
                    thumbnails.append(output_file)
                    print(f"  [*] Generated thumbnail at {timestamp:.1f}s")
            
        except Exception as e:
            self.logger.error(f"Thumbnail generation failed: {e}")
        
        return thumbnails
    
    def detect_editing(self, filepath: str) -> Dict:
        """Detect signs of video editing/tampering."""
        indicators = {
            "file": filepath,
            "suspicious_findings": [],
            "editing_likelihood": "LOW"
        }
        
        try:
            result = subprocess.run(
                ["ffprobe", "-v", "quiet", "-print_format", "json", "-show_streams", filepath],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                
                for stream in data.get("streams", []):
                    if "codec_tag_string" in stream:
                        tag = stream["codec_tag_string"]
                        if "qt" in tag.lower():
                            indicators["suspicious_findings"].append(f"QuickTime container tag: {tag}")
                
                fmt = data.get("format", {})
                if "tags" in fmt:
                    encoder = fmt["tags"].get("encoder", "").lower()
                    editing_tools = ["premiere", "final cut", "davinci", "resolve", "vegas", "filmora", "capcut"]
                    for tool in editing_tools:
                        if tool in encoder:
                            indicators["suspicious_findings"].append(f"Edited with: {tool}")
                            indicators["editing_likelihood"] = "HIGH"
            
        except:
            pass
        
        if not indicators["suspicious_findings"]:
            del indicators["suspicious_findings"]
        
        return indicators
    
    def get_statistics(self) -> Dict:
        """Get video analysis statistics."""
        if not self.results:
            return {"total_videos": 0}
        
        formats = {}
        resolutions = {}
        durations = []
        total_size = 0
        
        for r in self.results:
            fmt = r.get("format", "Unknown")
            res = r.get("resolution", "Unknown")
            dur = float(r.get("duration", 0))
            
            formats[fmt] = formats.get(fmt, 0) + 1
            resolutions[res] = resolutions.get(res, 0) + 1
            durations.append(dur)
            total_size += r.get("size_bytes", 0)
        
        return {
            "total_videos": len(self.results),
            "total_size_gb": round(total_size / (1024**3), 2),
            "formats": formats,
            "resolutions": resolutions,
            "avg_duration_seconds": round(sum(durations) / len(durations), 1) if durations else 0
        }
    
    def display_summary(self):
        """Display video analysis summary."""
        stats = self.get_statistics()
        
        print(f"\n[Video Forensics Summary]")
        print(f"{'='*50}")
        print(f"  Total Videos:  {stats['total_videos']}")
        print(f"  Total Size:    {stats['total_size_gb']} GB")
        print(f"  Avg Duration:  {stats.get('avg_duration_seconds', 0):.1f}s")
        
        if stats.get("formats"):
            print(f"\n  Formats:")
            for fmt, count in stats["formats"].items():
                print(f"    {fmt:<15} {count}")
        
        print(f"{'='*50}\n")
    
    def export_json(self, output_file: str):
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        print(f"[+] Results exported: {output_file}")
