Title: Database Harbor SysInfoDetectorX64.sys physical memory access

Vendor: Database Harbor Software
Product: SysInfo Detector
Component: SysInfoDetectorX64.sys
SHA-256: 45e5977b8d5baec776eb2e62a84981a8e46f6ce17947c9a76fa1f955dc547271
MD5: 33fc573c0e8bedfe3614e17219273429
SHA-1: 258f1cdc79bd20c2e6630a0865abfe60473b98d5
Size: 14608 bytes
PE timestamp: 2014-12-08 10:19:38 UTC
FileVersion: 2.0.0.3
ProductVersion: 2.0.0.3
OriginalFilename: SysInfoDetectorX64.sys
Authenticode status: Valid
Signer: CN=Database Harbor Software, OU=Digital ID Class 3 - Microsoft Software Validation v2, O=Database Harbor Software, L=Ulan-Ude, S=Buryatia, C=RU
Certificate thumbprint: 058E4B4E127D05A9B8526E3A07B753A928CADA73
Certificate not before: 2014-01-30 00:00:00 UTC
Certificate not after: 2017-03-30 23:59:59 UTC
Device: \\.\SysInfoDetector
PDB: c:\_work\_projects\sid_driver\sys\lib\amd64\SysInfoDetectorX64.pdb

CVE:

Description:
SysInfoDetectorX64.sys in Database Harbor Software SysInfo Detector FileVersion 2.0.0.3 (SHA-256 45e5977b8d5baec776eb2e62a84981a8e46f6ce17947c9a76fa1f955dc547271, 14608 bytes, PE timestamp 2014-12-08 10:19:38 UTC) passes a caller-supplied 32-bit physical address and a caller-supplied length to MmMapIoSpace on buffered IOCTL 0x22A4C0, clears the high 32 bits of that address before the call, does not validate the address range, and maps the range as non-cached, which allows a local user to read and write arbitrary physical memory at a caller-chosen 32-bit physical address and to escalate privileges locally via \\.\SysInfoDetector. The length is the caller-supplied access width (1, 2, or 4) multiplied by the caller-supplied count. The driver copies the caller bytes that follow those fields into the mapping and unmaps it before the call returns. Buffered IOCTL 0x226480 maps that same caller-supplied address and copies the bytes back to the caller. VERSIONINFO CompanyName is Database Harbor Software, ProductName is SysInfo Detector, FileDescription is Driver for SysInfo Detector, FileVersion and ProductVersion are 2.0.0.3, and OriginalFilename is SysInfoDetectorX64.sys. The Authenticode status is Valid, signed by CN=Database Harbor Software, OU=Digital ID Class 3 - Microsoft Software Validation v2, O=Database Harbor Software, L=Ulan-Ude, S=Buryatia, C=RU, thumbprint 058E4B4E127D05A9B8526E3A07B753A928CADA73. On 2026-11-03, on an isolated Windows 10 Enterprise LTSC 2021 virtual machine (10.0.19044.7807), an administrator loaded this file and the service started. The administrator locked one of its own pages at physical address 0xbefb3000 and did not send either IOCTL. Local account aida-low, a member of Users and not a member of Administrators, opened \\.\SysInfoDetector and sent IOCTL 0x22A4C0 for that address with width 1 and count 1, then sent IOCTL 0x226480. aida-low wrote 0x5A and read 0x5A back, then wrote 0xA5 and read 0xA5 back. The administrator read the first byte of that physical page and saw 0x5A, then 0xA5. The test did not show a crash. The device security descriptor was O:BAG:SYD:(A;;0x1201bf;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;RC)S:AI(ML;;NW;;;LW). Everyone (WD) has access mask 0x1201bf, which includes FILE_READ_DATA and FILE_WRITE_DATA.

Suggested fix: on IOCTL 0x22A4C0 and IOCTL 0x226480, map only a physical address chosen inside the driver, and limit access to \\.\SysInfoDetector to Administrators and SYSTEM.
