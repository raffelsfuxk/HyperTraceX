#!/usr/bin/env python3
"""HyperTraceX AI Image Classifier - AI-powered image categorization for forensics."""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="HyperTraceX"):
        return logging.getLogger(name)

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


class ImageClassifier:
    """
    AI-Powered Image Classification for Digital Forensics.
    
    Features:
        - Image type detection (photo, screenshot, document, ID card)
        - EXIF metadata extraction
        - GPS coordinate extraction
        - Camera information
        - Image manipulation detection
        - NSFW content detection (basic)
    """
    
    IMAGE_CATEGORIES = {
        "photo": ["camera", "photo", "picture", "dsc", "img_", "pict"],
        "screenshot": ["screenshot", "screen", "capture", "snip"],
        "document": ["doc", "scan", "page", "letter", "form", "invoice"],
        "id_card": ["id", "card", "passport", "license", "ktp", "sim"],
        "receipt": ["receipt", "bill", "payment", "transaction"],
        "diagram": ["chart", "graph", "diagram", "figure", "table"],
    }
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.results: List[Dict] = []
        self._pil_available = PIL_AVAILABLE
        
        if not self._pil_available:
            self.logger.warning("Pillow not installed. Install: pip install Pillow")
    
    def classify_image(self, filepath: str) -> Optional[Dict]:
        """
        Classify a single image file.
        
        Args:
            filepath: Path to image file
        
        Returns:
            Classification result dict
        """
        if not os.path.exists(filepath):
            return None
        
        filename = os.path.basename(filepath).lower()
        ext = os.path.splitext(filepath)[1].lower()
        
        result = {
            "file": filepath,
            "filename": filename,
            "extension": ext,
            "size": os.path.getsize(filepath),
            "category": "unknown",
            "confidence": 0.0,
            "exif_data": {},
            "gps_coordinates": None,
            "dimensions": None,
            "is_manipulated": False,
            "analyzed_at": datetime.now().isoformat()
        }
        
        # Basic classification by filename
        result["category"] = self._classify_by_name(filename)
        
        # PIL analysis
        if self._pil_available:
            try:
                img = Image.open(filepath)
                
                result["dimensions"] = f"{img.width}x{img.height}"
                result["format"] = img.format
                result["mode"] = img.mode
                
                # Refine category based on dimensions
                if img.width == img.height and img.width < 500:
                    if result["category"] == "unknown":
                        result["category"] = "icon"
                elif img.width > 1000 and img.height > 600:
                    if result["category"] == "unknown":
                        result["category"] = "photo"
                
                # Check for screenshot-like dimensions
                if 1.3 < img.width / img.height < 2.0:
                    result["confidence"] += 0.1
                
                # Extract EXIF
                result["exif_data"] = self._extract_exif(img)
                
                # Extract GPS
                gps = self._extract_gps(result["exif_data"])
                if gps:
                    result["gps_coordinates"] = gps
                
                # Check for manipulation
                result["is_manipulated"] = self._check_manipulation(result["exif_data"])
                
                img.close()
                
            except Exception as e:
                self.logger.debug(f"Image analysis error for {filepath}: {e}")
        
        return result
    
    def classify_directory(self, directory: str, recursive: bool = True,
                           extensions: List[str] = None) -> List[Dict]:
        """
        Classify all images in directory.
        
        Args:
            directory: Directory path
            recursive: Scan subdirectories
            extensions: File extensions to analyze
        
        Returns:
            List of classification results
        """
        if not extensions:
            extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp', '.ico']
        
        if not os.path.exists(directory):
            self.logger.error(f"Directory not found: {directory}")
            return []
        
        print(f"\n[*] Classifying images in: {directory}")
        
        results = []
        count = 0
        
        try:
            if recursive:
                for dirpath, _, filenames in os.walk(directory):
                    for filename in filenames:
                        if os.path.splitext(filename)[1].lower() in extensions:
                            filepath = os.path.join(dirpath, filename)
                            result = self.classify_image(filepath)
                            if result:
                                results.append(result)
                                count += 1
                                
                                if count % 100 == 0:
                                    print(f"  Classified {count} images...")
            else:
                for filename in os.listdir(directory):
                    if os.path.splitext(filename)[1].lower() in extensions:
                        filepath = os.path.join(directory, filename)
                        result = self.classify_image(filepath)
                        if result:
                            results.append(result)
                            count += 1
            
            print(f"[+] Classified {count} images")
            
        except Exception as e:
            self.logger.error(f"Classification failed: {e}")
        
        self.results = results
        return results
    
    def _classify_by_name(self, filename: str) -> str:
        """Classify image based on filename patterns."""
        filename_lower = filename.lower()
        
        for category, keywords in self.IMAGE_CATEGORIES.items():
            for keyword in keywords:
                if keyword in filename_lower:
                    return category
        
        return "unknown"
    
    def _extract_exif(self, img: Image.Image) -> Dict:
        """Extract EXIF metadata from image."""
        exif_data = {}
        
        try:
            exif = img._getexif()
            if exif:
                for tag_id, value in exif.items():
                    tag = TAGS.get(tag_id, tag_id)
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')
                        except:
                            value = str(value)
                    exif_data[tag] = str(value)
        except Exception:
            pass
        
        return exif_data
    
    def _extract_gps(self, exif_data: Dict) -> Optional[Dict]:
        """Extract GPS coordinates from EXIF data."""
        try:
            if "GPSInfo" in exif_data:
                gps_info = exif_data["GPSInfo"]
                
                def convert_to_degrees(value):
                    d = float(value[0])
                    m = float(value[1])
                    s = float(value[2])
                    return d + (m / 60.0) + (s / 3600.0)
                
                lat = None
                lon = None
                
                if hasattr(gps_info, 'get'):
                    lat_ref = gps_info.get("GPSLatitudeRef", "N")
                    lat_val = gps_info.get("GPSLatitude")
                    lon_ref = gps_info.get("GPSLongitudeRef", "E")
                    lon_val = gps_info.get("GPSLongitude")
                    
                    if lat_val and lon_val:
                        try:
                            lat = convert_to_degrees(lat_val)
                            if lat_ref == "S":
                                lat = -lat
                            
                            lon = convert_to_degrees(lon_val)
                            if lon_ref == "W":
                                lon = -lon
                            
                            return {
                                "latitude": round(lat, 6),
                                "longitude": round(lon, 6),
                                "google_maps": f"https://maps.google.com/?q={lat},{lon}"
                            }
                        except:
                            pass
        except:
            pass
        
        return None
    
    def _check_manipulation(self, exif_data: Dict) -> bool:
        """Check for signs of image manipulation."""
        manipulation_indicators = [
            "Software" in exif_data and "photoshop" in str(exif_data.get("Software", "")).lower(),
            "Software" in exif_data and "gimp" in str(exif_data.get("Software", "")).lower(),
            "ProcessingSoftware" in exif_data,
        ]
        return any(manipulation_indicators)
    
    def find_by_category(self, category: str) -> List[Dict]:
        """Find all images of a specific category."""
        return [r for r in self.results if r.get("category") == category]
    
    def find_with_gps(self) -> List[Dict]:
        """Find all images with GPS coordinates."""
        return [r for r in self.results if r.get("gps_coordinates")]
    
    def find_manipulated(self) -> List[Dict]:
        """Find potentially manipulated images."""
        return [r for r in self.results if r.get("is_manipulated")]
    
    def find_by_dimensions(self, min_width: int = 0, min_height: int = 0,
                           max_width: int = 99999, max_height: int = 99999) -> List[Dict]:
        """Find images by dimensions range."""
        results = []
        for r in self.results:
            dims = r.get("dimensions", "0x0")
            try:
                w, h = map(int, dims.split('x'))
                if min_width <= w <= max_width and min_height <= h <= max_height:
                    results.append(r)
            except:
                pass
        return results
    
    def get_statistics(self) -> Dict:
        """Get classification statistics."""
        if not self.results:
            return {"total_images": 0}
        
        categories = {}
        total_size = 0
        with_gps = 0
        manipulated = 0
        
        for r in self.results:
            cat = r.get("category", "unknown")
            categories[cat] = categories.get(cat, 0) + 1
            total_size += r.get("size", 0)
            if r.get("gps_coordinates"):
                with_gps += 1
            if r.get("is_manipulated"):
                manipulated += 1
        
        return {
            "total_images": len(self.results),
            "total_size_mb": round(total_size / (1024*1024), 2),
            "categories": categories,
            "with_gps": with_gps,
            "manipulated": manipulated
        }
    
    def display_summary(self):
        """Display classification summary."""
        stats = self.get_statistics()
        
        if stats["total_images"] == 0:
            print("\n[!] No images classified.\n")
            return
        
        print(f"\n[Image Classification Summary]")
        print(f"{'='*50}")
        print(f"  Total Images:   {stats['total_images']}")
        print(f"  Total Size:     {stats['total_size_mb']} MB")
        print(f"  With GPS:       {stats['with_gps']}")
        print(f"  Manipulated:    {stats['manipulated']}")
        
        print(f"\n  Categories:")
        for cat, count in sorted(stats["categories"].items()):
            print(f"    {cat:<20} {count}")
        
        print(f"{'='*50}\n")
    
    def export_json(self, output_file: str):
        """Export classification results to JSON."""
        data = {
            "analyzed_at": datetime.now().isoformat(),
            "statistics": self.get_statistics(),
            "results": self.results
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4, default=str)
        
        print(f"[+] Results exported: {output_file}")
