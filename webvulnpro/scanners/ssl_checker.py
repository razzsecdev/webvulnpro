"""
SSL/TLS Security Scanner - Certificate and Protocol Analysis
"""

import asyncio
import ssl
import socket
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict
from urllib.parse import urlparse

from ..core.models import Vulnerability, Severity


class SSLChecker:
    """SSL/TLS security analyzer"""
    
    # TLS protocol versions
    TLS_VERSIONS = {
        ssl.TLSVersion.TLSv1: ("TLS 1.0", True),  # (name, is_deprecated)
        ssl.TLSVersion.TLSv1_1: ("TLS 1.1", True),
        ssl.TLSVersion.TLSv1_2: ("TLS 1.2", False),
        ssl.TLSVersion.TLSv1_3: ("TLS 1.3", False),
    }
    
    # Weak cipher suites to check for
    WEAK_CIPHERS = [
        "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon", "ADH", "AECDH"
    ]
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
    
    async def scan(self, target: str) -> List[Vulnerability]:
        """Perform SSL/TLS security scan"""
        vulnerabilities = []
        
        # Parse target URL
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or 443
        
        if not host:
            return vulnerabilities
        
        # Run blocking SSL checks in executor
        loop = asyncio.get_event_loop()
        
        try:
            # Certificate checks
            cert_vulns = await loop.run_in_executor(
                None, self._check_certificate, host, port
            )
            vulnerabilities.extend(cert_vulns)
            
            # Protocol version checks
            proto_vulns = await loop.run_in_executor(
                None, self._check_protocols, host, port
            )
            vulnerabilities.extend(proto_vulns)
            
            # Cipher suite checks
            cipher_vulns = await loop.run_in_executor(
                None, self._check_ciphers, host, port
            )
            vulnerabilities.extend(cipher_vulns)
            
        except Exception as e:
            vulnerabilities.append(Vulnerability(
                title="SSL/TLS Connection Error",
                severity=Severity.INFO,
                cvss_score=0.0,
                description=f"Could not establish SSL connection: {str(e)}",
                remediation="Verify SSL/TLS is properly configured on the target.",
                evidence=str(e),
                category="SSL/TLS",
            ))
        
        return vulnerabilities
    
    def _check_certificate(self, host: str, port: int) -> List[Vulnerability]:
        """Check SSL certificate validity and configuration"""
        vulnerabilities = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cert_binary = ssock.getpeercert(binary_form=True)
                    
                    if cert:
                        # Check expiry
                        expiry_vulns = self._check_cert_expiry(cert, host)
                        vulnerabilities.extend(expiry_vulns)
                        
                        # Check hostname match
                        hostname_vulns = self._check_hostname_match(cert, host)
                        vulnerabilities.extend(hostname_vulns)
                        
                        # Check self-signed
                        self_signed_vulns = self._check_self_signed(cert, host)
                        vulnerabilities.extend(self_signed_vulns)
                    else:
                        # Try to get cert info another way
                        vulnerabilities.append(Vulnerability(
                            title="Certificate Information Unavailable",
                            severity=Severity.INFO,
                            cvss_score=0.0,
                            description="Could not retrieve certificate details for analysis.",
                            remediation="Certificate may be valid but details couldn't be parsed.",
                            evidence=f"Host: {host}:{port}",
                            category="SSL/TLS",
                        ))
        except ssl.SSLCertVerificationError as e:
            vulnerabilities.append(Vulnerability(
                title="SSL Certificate Verification Failed",
                severity=Severity.HIGH,
                cvss_score=7.4,
                description=f"SSL certificate verification failed: {str(e)}",
                remediation="Obtain and install a valid SSL certificate from a trusted CA.",
                evidence=str(e),
                category="SSL/TLS",
                cwe_id="CWE-295",
            ))
        except socket.timeout:
            vulnerabilities.append(Vulnerability(
                title="SSL Connection Timeout",
                severity=Severity.INFO,
                cvss_score=0.0,
                description=f"SSL connection to {host}:{port} timed out.",
                remediation="Check server availability and firewall rules.",
                evidence=f"Timeout: {self.timeout}s",
                category="SSL/TLS",
            ))
        except Exception as e:
            pass  # Handled by caller
        
        return vulnerabilities
    
    def _check_cert_expiry(self, cert: Dict, host: str) -> List[Vulnerability]:
        """Check certificate expiration"""
        vulnerabilities = []
        
        not_after = cert.get('notAfter')
        not_before = cert.get('notBefore')
        
        if not_after:
            try:
                # Parse date - format: 'MMM DD HH:MM:SS YYYY GMT'
                expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                now = datetime.now()
                days_until_expiry = (expiry - now).days
                
                if days_until_expiry < 0:
                    vulnerabilities.append(Vulnerability(
                        title="SSL Certificate Expired",
                        severity=Severity.CRITICAL,
                        cvss_score=9.1,
                        description=f"SSL certificate expired {abs(days_until_expiry)} days ago.",
                        remediation="Immediately renew the SSL certificate.",
                        evidence=f"Expiry: {not_after}",
                        category="SSL/TLS",
                        cwe_id="CWE-298",
                    ))
                elif days_until_expiry < 30:
                    vulnerabilities.append(Vulnerability(
                        title="SSL Certificate Expiring Soon",
                        severity=Severity.HIGH,
                        cvss_score=7.4,
                        description=f"SSL certificate expires in {days_until_expiry} days.",
                        remediation="Renew SSL certificate before expiration.",
                        evidence=f"Expiry: {not_after}",
                        category="SSL/TLS",
                        cwe_id="CWE-298",
                    ))
                elif days_until_expiry < 90:
                    vulnerabilities.append(Vulnerability(
                        title="SSL Certificate Expiring Within 90 Days",
                        severity=Severity.MEDIUM,
                        cvss_score=4.3,
                        description=f"SSL certificate expires in {days_until_expiry} days.",
                        remediation="Plan SSL certificate renewal.",
                        evidence=f"Expiry: {not_after}",
                        category="SSL/TLS",
                    ))
            except ValueError:
                pass
        
        return vulnerabilities
    
    def _check_hostname_match(self, cert: Dict, host: str) -> List[Vulnerability]:
        """Check if certificate hostname matches"""
        vulnerabilities = []
        
        subject = dict(x[0] for x in cert.get('subject', []))
        common_name = subject.get('commonName', '')
        
        # Get SANs
        san = cert.get('subjectAltName', [])
        san_hosts = [name for type_, name in san if type_ == 'DNS']
        
        all_names = [common_name] + san_hosts
        
        # Check if host matches any certificate name
        matched = False
        for name in all_names:
            if name.startswith('*.'):
                # Wildcard match
                pattern = name[2:]  # Remove *.
                if host.endswith(pattern) or host == pattern:
                    matched = True
                    break
            elif host.lower() == name.lower():
                matched = True
                break
        
        if not matched:
            vulnerabilities.append(Vulnerability(
                title="SSL Certificate Hostname Mismatch",
                severity=Severity.HIGH,
                cvss_score=7.4,
                description=f"Certificate common name '{common_name}' does not match host '{host}'.",
                remediation="Obtain a certificate that includes the correct hostname.",
                evidence=f"CN: {common_name}, SANs: {', '.join(san_hosts[:5])}",
                category="SSL/TLS",
                cwe_id="CWE-297",
            ))
        
        return vulnerabilities
    
    def _check_self_signed(self, cert: Dict, host: str) -> List[Vulnerability]:
        """Check for self-signed certificate"""
        vulnerabilities = []
        
        subject = dict(x[0] for x in cert.get('subject', []))
        issuer = dict(x[0] for x in cert.get('issuer', []))
        
        subject_cn = subject.get('commonName', '')
        issuer_cn = issuer.get('commonName', '')
        subject_o = subject.get('organizationName', '')
        issuer_o = issuer.get('organizationName', '')
        
        if subject_cn == issuer_cn and subject_o == issuer_o:
            vulnerabilities.append(Vulnerability(
                title="Self-Signed SSL Certificate",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                description="The SSL certificate appears to be self-signed.",
                remediation="Use a certificate from a trusted Certificate Authority.",
                evidence=f"Subject: {subject_cn}, Issuer: {issuer_cn}",
                category="SSL/TLS",
                cwe_id="CWE-295",
            ))
        
        return vulnerabilities
    
    def _check_protocols(self, host: str, port: int) -> List[Vulnerability]:
        """Check for deprecated TLS protocol versions"""
        vulnerabilities = []
        
        deprecated_supported = []
        
        # Check TLS 1.0
        if self._test_protocol(host, port, ssl.TLSVersion.TLSv1):
            deprecated_supported.append("TLS 1.0")
        
        # Check TLS 1.1
        if self._test_protocol(host, port, ssl.TLSVersion.TLSv1_1):
            deprecated_supported.append("TLS 1.1")
        
        if deprecated_supported:
            vulnerabilities.append(Vulnerability(
                title="Deprecated TLS Protocol Versions Supported",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                description=f"Server supports deprecated protocols: {', '.join(deprecated_supported)}",
                remediation="Disable TLS 1.0 and TLS 1.1. Only allow TLS 1.2 and TLS 1.3.",
                evidence=f"Supported deprecated: {', '.join(deprecated_supported)}",
                category="SSL/TLS",
                cwe_id="CWE-326",
                references=[
                    "https://tools.ietf.org/html/rfc8996",
                ],
            ))
        
        # Check if TLS 1.3 is NOT supported
        if not self._test_protocol(host, port, ssl.TLSVersion.TLSv1_3):
            vulnerabilities.append(Vulnerability(
                title="TLS 1.3 Not Supported",
                severity=Severity.LOW,
                cvss_score=3.1,
                description="Server does not support TLS 1.3, the latest protocol version.",
                remediation="Enable TLS 1.3 for improved security and performance.",
                evidence=f"Host: {host}:{port}",
                category="SSL/TLS",
            ))
        
        return vulnerabilities
    
    def _test_protocol(self, host: str, port: int, version: ssl.TLSVersion) -> bool:
        """Test if a specific TLS version is supported"""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version
            context.maximum_version = version
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return True
        except:
            return False
    
    def _check_ciphers(self, host: str, port: int) -> List[Vulnerability]:
        """Check for weak cipher suites"""
        vulnerabilities = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name, protocol, bits = cipher
                        
                        # Check for weak ciphers
                        for weak in self.WEAK_CIPHERS:
                            if weak.upper() in cipher_name.upper():
                                vulnerabilities.append(Vulnerability(
                                    title=f"Weak Cipher Suite in Use: {weak}",
                                    severity=Severity.MEDIUM,
                                    cvss_score=5.3,
                                    description=f"Server negotiated weak cipher: {cipher_name}",
                                    remediation="Disable weak ciphers and use only strong cipher suites.",
                                    evidence=f"Cipher: {cipher_name}, Bits: {bits}",
                                    category="SSL/TLS",
                                    cwe_id="CWE-327",
                                ))
                                break
                        
                        # Check key size
                        if bits and bits < 128:
                            vulnerabilities.append(Vulnerability(
                                title="Weak Cipher Key Size",
                                severity=Severity.HIGH,
                                cvss_score=7.4,
                                description=f"Cipher uses weak key size: {bits} bits",
                                remediation="Use cipher suites with at least 128-bit keys.",
                                evidence=f"Cipher: {cipher_name}, Bits: {bits}",
                                category="SSL/TLS",
                                cwe_id="CWE-326",
                            ))
        except:
            pass
        
        return vulnerabilities
