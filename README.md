# Passbolt Key Manager for C# .Net 7

## Overview

The `PassboltKeyManager` for C# provides an interface to manage keys and interact with the Passbolt API. This project was initiated due to the absence of an official C# .Net SDK for Passbolt, filling a vital gap for .NET developers looking to integrate with the Passbolt ecosystem.

## Table of Contents

- [Overview](#overview)
- [Features](#features)  
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Class Documentation](#class-documentation)
  - [Prerequisites](#prerequisites-1)
  - [Instantiating PassboltKeyManager](#instantiating-passboltkeymanager)
  - [Methods](#methods)
  - [Implementation Details](#implementation-details)
  - [Error Handling](#error-handling)
  - [Class Structure](#class-structure)
- [License](#license)
- [Acknowledgements](#acknowledgements)

## Features  

- Authenticate with the Passbolt server using a GPG key handshake
- Generate a 256-bit AES key  
- Check the existence of a resource on the Passbolt server
- Encrypt and decrypt data using PGP public and private keys
- Fetch encryption keys associated with Passbolt resources
- Create new resources with encryption keys on Passbolt

## Prerequisites

- .NET SDK
- Org.BouncyCastle library

## Installation

To utilize the `PassboltKeyManager`, you'll need to ensure your project references the necessary libraries. For instance, you can install the required libraries via NuGet:

```
Install-Package [Package-Name]
```

Replace `[Package-Name]` with the appropriate library names.

## Configuration  

Ensure your configuration file (e.g. `appsettings.json`) is set up with the required parameters:

```json
{
  "PassboltUrl": "YOUR_PASSBOLT_URL",
  "UserGpgPublicKey": "YOUR_GPG_PUBLIC_KEY",
  "UserGpgPrivateKey": "YOUR_GPG_PRIVATE_KEY",
  "UserGpgPassPhrase": "YOUR_GPG_PASSPHRASE"
}
```

## Usage

Create an instance of `PassboltKeyManager` and call its methods as needed:

```csharp
var manager = new PassboltKeyManager();

// Authentication example
bool isAuthenticated = await manager.AuthenticationWithPassbolt();

// Generate AES key example
byte[] key = manager.GenerateAES256Key();

// Check resource exists example 
bool exists = await manager.CheckResourceExists("resourceName");

// Encrypt example
string encrypted = manager.Encrypt("data", "publicKey");

// Decrypt example
string decrypted = manager.Decrypt(encrypted, "privateKey");
```

## Class Documentation

The `PassboltKeyManager` class provides utilities to integrate with Passbolt, a password manager for teams. It handles authentication with the Passbolt server using GPG key handshake and manages cryptographic operations for the server-client communication.

### Prerequisites

Ensure you have the following namespaces imported:

```csharp
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security; 
using System;
using System.IO;
using System.Text;
using System.Net.Http;
using System.Threading.Tasks;
using System.Text.Json;
using System.Security.Cryptography;
using Cryptography.Interfaces;
using System.Linq;
```

### Instantiating PassboltKeyManager

```csharp  
var manager = new PassboltKeyManager();
```

### Methods

See the [Usage](#usage) section for examples.

#### AuthenticationWithPassbolt()

Authenticates with the Passbolt server using a GPG key handshake. Returns `true` if successful. 

#### GenerateAES256Key()

Generates a 256-bit AES key.

#### CheckResourceExists(string resourceName)

Checks if a resource exists on Passbolt. Returns `true` if exists.

#### FetchKeyFromPassbolt(string resourceName)

Fetches the encryption key for a Passbolt resource.

#### CreateResourceInPassbolt(string resourceName, byte[]? encryptionKey = null)

Creates a new resource in Passbolt with an encryption key.

#### Encrypt(string data, string publicKey) 

Encrypts data with a public key. Returns encrypted data.

#### Decrypt(string encryptedData, string privateKey)

Decrypts data with a private key. Returns decrypted data.

### Implementation Details

Uses BouncyCastle library. Configuration extracted from `Configuration.Config`. Authenticates via encrypting/decrypting random strings. Provides utilities for Passbolt resources and encryption.

### Error Handling

Cryptographic operations throw `CryptographicException`. API errors throw `HttpRequestException`.

### Class Structure

- `VerifyServer()`: Verifies Passbolt server.
- `IsValidResourceResponse()`: Validates resource check responses. 
- `ServerInfo`: Info received from Passbolt server.
- `PassboltResource`: Represents a Passbolt resource.
- `Secret`: Represents a secret for a resource.

## License

This project is licensed under the GNU AFFERO GENERAL PUBLIC LICENSE 3.0 License. See [LICENSE](LICENSE) for details.

## Acknowledgements

This project uses cryptographic libraries such as [BouncyCastle](https://www.bouncycastle.org/) for some of its operations.
For more details and support, please refer to the official documentation or contact the maintainers.