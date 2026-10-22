# SecureTracer — Project Details

**Project:** SecureTracer  
**Category:** File and endpoint security

## What I made
SecureTracer is a small endpoint security project for protecting important files and checking suspicious device activity. The main part of the project uses SHA-256 to check whether a protected file has changed. A Python agent also watches USB activity and sends events to the web dashboard.

The ML part gives a simple risk estimate from recent security events. It is meant as a practical college-project feature, not as a replacement for a full enterprise security product.

## Main parts
- File protection and SHA-256 verification
- USB/removable-drive monitoring
- Security event and alert logging
- Simple ML-based risk check
- React dashboard
- Node.js/Express API
- MongoDB storage
- Hash-chained audit records

## Viva line
“First I register an important file and store its SHA-256 hash. When I check it again, the new hash is compared with the old one. If the hashes are different, the system reports a tampering event. The endpoint agent also watches USB activity and the ML module gives a risk level from recent events.”
