# PHP-Hash
[![Packgist](https://img.shields.io/packagist/v/carry0987/hash.svg?style=flat-square)](https://packagist.org/packages/carry0987/hash)  
PHP-Hash is a comprehensive library designed to facilitate the generation of securely encrypted URLs. With support for customizable encryption algorithms and AEAD (Authenticated Encryption with Additional Data) cipher modes, it offers flexibility while ensuring the integrity and authenticity of the data.

## Features
- Easy generation of encrypted URLs.
- Support for a variety of encryption algorithms and AEAD cipher modes.
- Customizable prefixes, suffixes, and path formatting for encrypted URLs.
- Integration with the Composer package manager for straightforward installation.

## Installation
Use Composer to install PHP-Hash in your project:
```shell
composer require carry0987/hash
```

## Usage
To use PHP-Hash to generate encrypted URLs, follow these steps:

1. **Initialization**:
```php
use carry0987\Hash\Hash;

// Initialize with your signature key and signature salt
$hash = new Hash('your_hex_signature_key', 'your_hex_signature_salt');
```

2. **Configuration** (Optional):
   Customize encryption settings as needed.
```php
// Set a custom encryption cipher
$hash->setCipher('aes-256-gcm');

// Set a custom encryption algorithm for generating binary signatures
$hash->setEncryptAlgorithm('sha256');

// Optionally, set a custom Additional Authenticated Data (AAD) for AEAD ciphers
$hash->setAAD('your_custom_aad');

// Customize the encrypted path's prefix and suffix
$hash->setPrefix('/custom-prefix');
$hash->setSuffix('/custom-suffix');
```

3. **Generate Encrypted URL**:
```php
$originalUrl = 'https://yourdomain.com/original/path';
$encryptedUrl = $hash->generateEncryptedUrl($originalUrl);
echo $encryptedUrl;
```

## Custom Path Formatting
PHP-Hash allows for custom formatting of the encrypted path through a user-defined callback function:
```php
$hash->setPathFormatter(function ($encryptedUrl, $options) {
    // Your custom logic here
    return "/custom/format/$encryptedUrl";
});
```

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
