# CypherHawk DPI Testing Guide

This guide helps you set up realistic DPI testing environments to validate CypherHawk's corporate Deep Packet Inspection detection capabilities. You'll simulate enterprise security infrastructure without needing expensive commercial solutions.

## 🎯 Overview

CypherHawk is designed to detect corporate DPI/MitM proxies and extract their CA certificates for Java application compatibility. To properly test and validate this functionality, you need realistic test environments that simulate how enterprise security solutions work.

> **For Developers:** Working on CypherHawk itself? See [INTERNAL-DPI-TESTING.md](INTERNAL-DPI-TESTING.md) for the internal Go test framework and automated DPI simulations.

## 🏗️ Testing Approaches

We provide **three testing approaches** from easiest to most realistic:

### 1. 🚀 Go Test Server (Easiest)

```
┌─────────────┐    HTTPS Request    ┌─────────────────┐
│  CypherHawk │ ──────────────────► │ Go Test Server  │
│             │ ◄────────────────── │   (localhost)   │
└─────────────┘   Custom CA Cert    └─────────────────┘
                                            │
                                            ▼
                                    ┌─────────────────┐
                                    │ Self-signed CA  │
                                    │ • Palo Alto     │
                                    │ • Zscaler       │
                                    │ • Generic Corp  │
                                    │ • Malicious DPI │
                                    └─────────────────┘
```

- **Best for:** Quick validation, no Docker required
- **Simulates:** Basic corporate DPI with custom root CAs
- **Time:** 5 minutes setup
- **No system certificates:** Certificates only exist during test

### 2. 🐳 mitmproxy (Recommended)

```
┌─────────────┐   HTTP(S) Request   ┌─────────────────┐   Real HTTPS    ┌──────────────┐
│  CypherHawk │ ──────────────────► │    mitmproxy    │ ──────────────► │ Real Server  │
│             │ ◄────────────────── │   (Port 8080)   │ ◄────────────── │ (google.com) │
└─────────────┘  Intercepted Cert   └─────────────────┘  Original Cert  └──────────────┘
                                            │
                                            ▼
                                    ┌─────────────────┐
                                    │Corporate CA Cert│
                                    │ • Dynamic Cert  │
                                    │   Generation    │
                                    │ • SSL Intercept │
                                    │ • Real Proxy    │
                                    │   Behavior      │
                                    └─────────────────┘
```

- **Best for:** Realistic HTTPS interception testing
- **Simulates:** Modern corporate proxies like Zscaler, Netskope
- **Time:** 15 minutes setup
- **System integration:** Installs CA in system trust store

### 3. 🌐 Squid Proxy (Most Realistic)

```
┌─────────────┐   HTTP CONNECT     ┌─────────────────┐  TLS Handshake  ┌──────────────┐
│  CypherHawk │ ─────────────────► │   Squid Proxy   │ ──────────────► │ Real Server  │
│             │ ◄───────────────── │   (Port 3128)   │ ◄────────────── │ (google.com) │
└─────────────┘  SSL Bump + Cert   └─────────────────┘  Server Cert    └──────────────┘
                                           │
                                           ▼
                                   ┌─────────────────┐
                                   │ SSL Certificate │
                                   │ Manipulation    │
                                   │ • SSL Bumping   │
                                   │ • Cert Signing  │
                                   │ • Enterprise    │
                                   │   DPI Behavior  │
                                   └─────────────────┘
```

- **Best for:** Most realistic corporate environment simulation
- **Simulates:** Traditional enterprise proxies like BlueCoat, Forcepoint
- **Time:** 30 minutes setup
- **Full enterprise simulation:** Complete SSL bumping and certificate manipulation

## 🖥️ Platform-Specific Guides

Choose your platform for detailed setup instructions:

| Platform | Guide | Key Features |
|----------|-------|-------------|
| **Windows** | [DPI-TESTING-WINDOWS.md](DPI-TESTING-WINDOWS.md) | PowerShell scripts, Windows Certificate Store, Docker Desktop |
| **macOS** | [DPI-TESTING-MACOS.md](DPI-TESTING-MACOS.md) | Keychain Access, macOS security, Apple Silicon support |
| **Linux** | [DPI-TESTING-LINUX.md](DPI-TESTING-LINUX.md) | System certificate stores, package managers, containerized testing |

## 🔍 What You'll Validate

Each testing approach helps you verify:

- **✅ DPI Detection** - CypherHawk correctly identifies corporate MitM
- **✅ CA Extraction** - Unknown certificates are properly extracted
- **✅ Vendor Identification** - Corporate DPI vendors are recognized  
- **✅ Security Analysis** - Behavioral analysis detects suspicious certificates
- **✅ HawkScan Integration** - Extracted certificates work with Java applications

## 📋 Quick Start

1. **Choose your platform** from the guides above
2. **Select testing approach** based on your needs and time
3. **Follow platform-specific instructions** for setup
4. **Test CypherHawk detection** against your simulated DPI
5. **Clean up certificates** using the detailed cleanup instructions

## ⚠️ Important Security Notes

- **Test environments only** - These setups create intentionally vulnerable certificates
- **Clean up thoroughly** - Remove test certificates from your system trust store  
- **Isolated testing** - Use dedicated VMs or containers when possible
- **Network isolation** - Don't expose test proxies to production networks

## 🆘 Troubleshooting

**Common issues across all platforms:**

- **Port conflicts**: DPI testing uses ports 8080, 8443, 8446-8447
- **Certificate warnings**: Browser warnings are expected and normal
- **Docker issues**: Ensure Docker Desktop is running and updated
- **Permission errors**: Some operations require administrator/root access

**Platform-specific troubleshooting** is included in each platform guide.

## 🔧 Advanced Testing

For comprehensive validation:

1. **Test multiple DPI vendors** using different profiles (Palo Alto, Zscaler, etc.)
2. **Validate with real Java apps** using extracted certificates
3. **Test network conditions** with proxy authentication and timeouts  
4. **Cross-platform validation** using multiple operating systems

## 📚 Related Documentation

- [README.md](../README.md) - Main project documentation
- [BUILD.md](BUILD.md) - Building CypherHawk from source
- [CLAUDE.md](../CLAUDE.md) - Development context and architecture

---

**Ready to start?** Choose your platform guide above and begin testing CypherHawk's DPI detection capabilities in realistic corporate environments.