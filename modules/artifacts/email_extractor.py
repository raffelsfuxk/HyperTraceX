#!/usr/bin/env python3
"""HyperTraceX Email Extractor - Extract emails from Outlook PST and Thunderbird MBOX."""

import os
import re
import email
from email import policy
from email.parser import BytesParser
from datetime import datetime
from typing import Dict, List, Optional
import mailbox

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="HyperTraceX"):
        return logging.getLogger(name)


class EmailExtractor:
    """
    Email Forensic Extractor.
    
    Extracts emails from:
        - Outlook PST/OST files (via pypff/libpff)
        - Thunderbird MBOX files
        - Windows Mail files
        - EML files
    
    Recovers email metadata, attachments, and headers.
    """
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.extracted_emails: List[Dict] = []
        self.extracted_attachments: List[Dict] = []
    
    def extract_pst(self, pst_file: str, output_dir: Optional[str] = None) -> List[Dict]:
        """
        Extract emails from Outlook PST/OST file.
        
        Requires: pypff (libpff) - sudo apt install python3-pypff
        """
        emails = []
        
        if not os.path.exists(pst_file):
            self.logger.error(f"PST file not found: {pst_file}")
            return emails
        
        print(f"\n[*] Extracting PST: {os.path.basename(pst_file)}")
        
        try:
            import pypff
            
            pst = pypff.file()
            pst.open(pst_file)
            root = pst.get_root_folder()
            
            def process_folder(folder, depth=0):
                for subfolder in folder.sub_folders:
                    process_folder(subfolder, depth + 1)
                
                for message in folder.sub_messages:
                    try:
                        email_data = {
                            "subject": message.get_subject() or "(No Subject)",
                            "sender": message.get_sender_name() or "",
                            "sender_email": "",
                            "recipients": [],
                            "cc": [],
                            "bcc": [],
                            "date": None,
                            "body": "",
                            "has_attachments": False,
                            "attachment_count": 0,
                            "attachments": [],
                            "headers": {},
                            "importance": "Normal",
                            "read": False
                        }
                        
                        # Parse sender
                        sender = message.get_sender_name() or ""
                        email_match = re.search(r'<(.+?)>', sender)
                        if email_match:
                            email_data["sender_email"] = email_match.group(1)
                        
                        # Recipients
                        try:
                            recipients = message.get_recipients()
                            if recipients:
                                email_data["recipients"] = [
                                    {"name": r.get_name(), "email": r.get_email()}
                                    for r in recipients.values()
                                ]
                        except:
                            pass
                        
                        # Date
                        try:
                            email_data["date"] = message.get_delivery_time().isoformat()
                        except:
                            pass
                        
                        # Body
                        try:
                            email_data["body"] = message.get_plain_text_body()[:5000]
                        except:
                            try:
                                email_data["body"] = message.get_html_body()[:5000]
                            except:
                                pass
                        
                        # Attachments
                        try:
                            attachments = message.get_attachments()
                            if attachments:
                                email_data["has_attachments"] = True
                                email_data["attachment_count"] = len(attachments)
                                
                                for att in attachments:
                                    att_info = {
                                        "filename": att.get_name() or "unnamed",
                                        "size": att.get_size() or 0,
                                        "mime_type": ""
                                    }
                                    email_data["attachments"].append(att_info)
                                    
                                    # Save attachment if output_dir specified
                                    if output_dir:
                                        os.makedirs(output_dir, exist_ok=True)
                                        safe_name = re.sub(r'[<>:"/\\|?*]', '_', att_info["filename"])
                                        att_path = os.path.join(output_dir, safe_name)
                                        try:
                                            with open(att_path, 'wb') as f:
                                                f.write(att.get_data())
                                            att_info["saved_to"] = att_path
                                        except:
                                            pass
                        except:
                            pass
                        
                        emails.append(email_data)
                        
                        if len(emails) % 100 == 0:
                            print(f"  Extracted {len(emails)} emails...")
                            
                    except Exception as e:
                        self.logger.debug(f"Message extraction error: {e}")
            
            process_folder(root)
            pst.close()
            
            print(f"[+] PST extraction complete: {len(emails)} emails")
            
        except ImportError:
            self.logger.warning("pypff not installed. Install: sudo apt install python3-pypff")
            print("[!] pypff library required for PST extraction")
        except Exception as e:
            self.logger.error(f"PST extraction failed: {e}")
        
        self.extracted_emails.extend(emails)
        return emails
    
    def extract_mbox(self, mbox_file: str, output_dir: Optional[str] = None) -> List[Dict]:
        """
        Extract emails from MBOX file (Thunderbird, etc.).
        """
        emails = []
        
        if not os.path.exists(mbox_file):
            self.logger.error(f"MBOX file not found: {mbox_file}")
            return emails
        
        print(f"\n[*] Extracting MBOX: {os.path.basename(mbox_file)}")
        
        try:
            mbox = mailbox.mbox(mbox_file)
            
            for i, msg in enumerate(mbox):
                try:
                    email_data = {
                        "subject": msg.get("Subject", "(No Subject)"),
                        "sender": msg.get("From", ""),
                        "sender_email": "",
                        "recipients": [],
                        "cc": msg.get("Cc", ""),
                        "date": msg.get("Date", ""),
                        "body": "",
                        "has_attachments": False,
                        "attachment_count": 0,
                        "attachments": [],
                        "headers": dict(msg.items()),
                        "message_id": msg.get("Message-ID", "")
                    }
                    
                    # Parse sender email
                    sender = msg.get("From", "")
                    email_match = re.search(r'<(.+?)>', sender)
                    if email_match:
                        email_data["sender_email"] = email_match.group(1)
                    
                    # Parse recipients
                    to = msg.get("To", "")
                    for addr in to.split(","):
                        addr = addr.strip()
                        if addr:
                            email_data["recipients"].append(addr)
                    
                    # Parse body
                    body_parts = []
                    if msg.is_multipart():
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            content_disposition = str(part.get("Content-Disposition", ""))
                            
                            if "attachment" in content_disposition:
                                filename = part.get_filename()
                                if filename:
                                    att_info = {
                                        "filename": filename,
                                        "size": len(part.get_payload(decode=True) or b""),
                                        "mime_type": content_type
                                    }
                                    email_data["attachments"].append(att_info)
                                    email_data["attachment_count"] += 1
                                    
                                    if output_dir:
                                        os.makedirs(output_dir, exist_ok=True)
                                        safe_name = re.sub(r'[<>:"/\\|?*]', '_', filename)
                                        att_path = os.path.join(output_dir, safe_name)
                                        try:
                                            with open(att_path, 'wb') as f:
                                                f.write(part.get_payload(decode=True))
                                            att_info["saved_to"] = att_path
                                        except:
                                            pass
                            
                            elif content_type == "text/plain":
                                try:
                                    body_parts.append(part.get_payload(decode=True).decode('utf-8', errors='ignore'))
                                except:
                                    pass
                    else:
                        try:
                            body_parts.append(msg.get_payload(decode=True).decode('utf-8', errors='ignore'))
                        except:
                            pass
                    
                    email_data["body"] = '\n'.join(body_parts)[:5000]
                    email_data["has_attachments"] = email_data["attachment_count"] > 0
                    
                    emails.append(email_data)
                    
                    if (i + 1) % 100 == 0:
                        print(f"  Extracted {i + 1} emails...")
                        
                except Exception as e:
                    self.logger.debug(f"Message extraction error: {e}")
            
            print(f"[+] MBOX extraction complete: {len(emails)} emails")
            
        except Exception as e:
            self.logger.error(f"MBOX extraction failed: {e}")
        
        self.extracted_emails.extend(emails)
        return emails
    
    def extract_eml(self, eml_file: str) -> Optional[Dict]:
        """Extract a single EML email file."""
        if not os.path.exists(eml_file):
            return None
        
        try:
            with open(eml_file, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
            
            email_data = {
                "subject": msg.get("Subject", "(No Subject)"),
                "sender": msg.get("From", ""),
                "date": msg.get("Date", ""),
                "recipients": [msg.get("To", "")],
                "cc": msg.get("Cc", ""),
                "body": "",
                "headers": dict(msg.items())
            }
            
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        try:
                            email_data["body"] = part.get_content()
                        except:
                            pass
            else:
                try:
                    email_data["body"] = msg.get_content()
                except:
                    pass
            
            return email_data
            
        except Exception as e:
            self.logger.error(f"EML extraction failed: {e}")
            return None
    
    def search_emails(self, keyword: str, field: str = "all") -> List[Dict]:
        """
        Search extracted emails.
        
        Args:
            keyword: Search term
            field: Field to search (subject, sender, body, all)
        
        Returns:
            Matching emails
        """
        results = []
        keyword_lower = keyword.lower()
        
        for msg in self.extracted_emails:
            match = False
            
            if field in ["subject", "all"]:
                if keyword_lower in msg.get("subject", "").lower():
                    match = True
            
            if field in ["sender", "all"]:
                if keyword_lower in msg.get("sender", "").lower():
                    match = True
            
            if field in ["body", "all"]:
                if keyword_lower in msg.get("body", "").lower():
                    match = True
            
            if match:
                results.append(msg)
        
        return results
    
    def get_statistics(self) -> Dict:
        """Get extraction statistics."""
        total = len(self.extracted_emails)
        with_attachments = sum(1 for e in self.extracted_emails if e.get("has_attachments"))
        total_attachments = sum(e.get("attachment_count", 0) for e in self.extracted_emails)
        
        # Date range
        dates = [e.get("date") for e in self.extracted_emails if e.get("date")]
        
        # Top senders
        senders = {}
        for e in self.extracted_emails:
            sender = e.get("sender_email") or e.get("sender", "Unknown")
            senders[sender] = senders.get(sender, 0) + 1
        top_senders = sorted(senders.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            "total_emails": total,
            "with_attachments": with_attachments,
            "total_attachments": total_attachments,
            "date_range": {
                "earliest": min(dates) if dates else None,
                "latest": max(dates) if dates else None
            },
            "top_senders": top_senders
        }
    
    def display_summary(self):
        """Display extraction summary."""
        stats = self.get_statistics()
        
        print(f"\n[Email Extraction Summary]")
        print(f"{'='*50}")
        print(f"  Total Emails:    {stats['total_emails']}")
        print(f"  With Attachments: {stats['with_attachments']}")
        print(f"  Total Attachments: {stats['total_attachments']}")
        
        if stats['date_range']['earliest']:
            print(f"  Date Range:")
            print(f"    Earliest: {stats['date_range']['earliest']}")
            print(f"    Latest:   {stats['date_range']['latest']}")
        
        if stats['top_senders']:
            print(f"\n  Top Senders:")
            for sender, count in stats['top_senders'][:5]:
                print(f"    {sender[:40]:<40} {count}")
        
        print(f"{'='*50}\n")
    
    def clear(self):
        """Clear extracted data."""
        self.extracted_emails.clear()
        self.extracted_attachments.clear()
