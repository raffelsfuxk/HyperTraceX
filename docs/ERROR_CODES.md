# HyperTraceX Error Codes & Troubleshooting

## Error Codes

| Code | Description | Solution |
|------|-------------|----------|
| E001 | Root privileges required | Run with: sudo tracex |
| E002 | Missing dependency | Run: sudo bash install.sh |
| E003 | Source path not found | Verify source path exists |
| E004 | Destination not writable | Check permissions on output directory |
| E005 | Hash mismatch | Evidence may be compromised |
| E006 | Mount failed | Check filesystem type and permissions |
| E007 | Python module missing | Run: pip install -r requirements.txt |
| E008 | Database locked | Close other HyperTraceX instances |
| E009 | Plugin load failed | Check plugin syntax |
| E010 | API server error | Check port availability |

## Common Issues

### Blackscreen / GUI Issues (Kali/Parrot VM)
- Restart display manager: `sudo systemctl restart lightdm`
- Reinstall desktop: `sudo apt install --reinstall kali-desktop-xfce`

### Permission Denied
- HyperTraceX requires root privileges
- Evidence drives must be readable
- Output directory must be writable

### Module Not Found
- Ensure all core files are present
- Check Python path: `sys.path`
- Reinstall: `sudo bash install.sh`

### Memory Dump Failed
- LiME kernel module required
- Some memory regions may be protected
- Try alternative method: `/proc/kcore`

## Support

- GitHub Issues: https://github.com/raffelsfuxk/HyperTraceX/issues
- Documentation: https://github.com/raffelsfuxk/HyperTraceX/wiki
