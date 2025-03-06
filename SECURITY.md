# Security Guide

## Key Management
- Encrypt private keys with passwords
- Store keys with proper file permissions
- Implement key rotation policies

## JWT Security
- RS256 (RSA Signature with SHA-256) for signatures
- One-time nonces prevent replay attacks
- JWT expiration prevents long-term token abuse

## Network Security
- Use HTTPS in production
- Configure CORS with appropriate origins
- Validate all user inputs

## Database Security
- Use a robust database like PostgreSQL with proper encryption and access controls in production
- Use parameterized queries to prevent SQL injection
- Consider database encryption for sensitive data

## Logging
- Avoid logging sensitive information
- Implement audit logging for key operations

## Possible Enhancements
- User authentication for key management
- Hardware security module (HSM) support
- Security monitoring and alerting
