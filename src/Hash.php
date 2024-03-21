<?php
namespace carry0987\Hash;

use carry0987\Hash\Utils\HTTPUtil;
use carry0987\Hash\Exceptions\HashException;

class Hash
{
    // Signature and encryption keys
    protected string $signatureKey;
    protected string $signatureSalt;
    protected string $sourceKey;

    // Encryption options
    protected string $encryptAlgorithm = 'sha256'; // Default encryption algorithm
    protected string $cipher = 'aes-256-gcm'; // Default encryption method
    protected ?string $aad = null; // Default AAD

    // Custom prefix and suffix for encryptedPath
    protected ?string $prefix = null; // Custom prefix for encryptedPath
    protected ?string $suffix = null; // Custom suffix for encryptedPath
    protected $pathFormatterCallback = null; // Custom path formatter callback

    /**
     * Hash constructor.
     * @param string $signatureKey Hexadecimal signature key.
     * @param string $signatureSalt Hexadecimal signature salt.
     * @param string|null $sourceKey Hexadecimal source key.
     */
    public function __construct(string $signatureKey, string $signatureSalt, string $sourceKey = null)
    {
        $this->signatureKey = hex2bin($signatureKey);
        $this->signatureSalt = hex2bin($signatureSalt);

        // Set source key if provided
        if ($sourceKey !== null) {
            $this->setSourceKey($sourceKey);
        }
    }

    /**
     * Set the encryption algorithm to be used for hashing.
     * 
     * @param string $algorithm The encryption algorithm.
     * 
     * @return $this
     */
    public function setEncryptAlgorithm(string $algorithm)
    {
        if (!in_array($algorithm, hash_hmac_algos())) {
            throw new HashException('Invalid encryption algorithm.');
        }
        $this->encryptAlgorithm = $algorithm;

        return $this;
    }

    /**
     * Set the encryption cipher to be used.
     * @param string $cipher The cipher method.
     * 
     * @return $this
     */
    public function setCipher(string $cipher)
    {
        if (!in_array($cipher, openssl_get_cipher_methods())) {
            throw new HashException('Invalid encryption cipher.');
        }
        $this->cipher = $cipher;

        return $this;
    }

    public function setSourceKey(string $sourceKey)
    {
        $this->sourceKey = hex2bin($sourceKey);

        return $this;
    }

    public function setAAD(string $aad)
    {
        // If current cipher is not AEAD, AAD should not be set
        if (!$this->isAEADCipher($this->cipher)) {
            throw new HashException('AAD should not be set for non-AEAD ciphers.');
        }
        $this->aad = $aad;

        return $this;
    }

    /**
     * Set a custom prefix for the encrypted path.
     * 
     * @param string $prefix The custom prefix.
     * 
     * @return $this
     */
    public function setPrefix(string $prefix)
    {
        $this->prefix = rtrim($prefix, '/');

        return $this;
    }

    /**
     * Set a custom suffix for the encrypted path.
     * 
     * @param string $suffix The custom suffix.
     * 
     * @return $this
     */
    public function setSuffix(string $suffix)
    {
        $this->suffix = ltrim($suffix, '/');

        return $this;
    }

    /**
     * Set the callback function for customizing the encrypted path format.
     * 
     * @param callable $formatterCallback The callback function that formats the encrypted path.
     *        The callback function should accept two parameters:
     *        - $encryptedUrl: The base64 encoded encrypted URL.
     *        - $options: An optional options array for further customization.
     * 
     * @return $this
     */
    public function setPathFormatter(callable $formatterCallback)
    {
        $this->pathFormatterCallback = $formatterCallback;

        return $this;
    }

    /**
     * Generate an encrypted URL to be used with Hash.
     * @param string $originalUrl The original URL.
     * 
     * @return string The signed encrypted URL.
     * 
     * @throws HashException If encryption fails or binary signature cannot be generated.
     */
    public function generateURL(string $originalUrl)
    {
        $encryptedBinaryUrl = self::encryptData($originalUrl, $this->sourceKey ?? $this->signatureKey);
        $encryptedUrl = HTTPUtil::base64UrlEncode($encryptedBinaryUrl);

        // Format the encrypted path and append the signature
        $encryptedPath = $this->formatEncryptedPath($encryptedUrl);

        $binarySignature = hash_hmac($this->encryptAlgorithm, $this->signatureSalt.$encryptedPath, $this->signatureKey, true);
        if ($binarySignature === false) {
            throw new HashException('Could not generate binary signature.');
        }
        $signature = HTTPUtil::base64UrlEncode($binarySignature);

        return sprintf("/%s%s", $signature, $encryptedPath);
    }

    /**
     * Build encryption options based on the selected cipher.
     * 
     * @return array Options including ivLength, tagLength (if applicable), and aad.
     */
    private function buildEncryptOptions()
    {
        $ivLength = openssl_cipher_iv_length($this->cipher);
        $tagLength = $this->isAEADCipher($this->cipher) ? $this->getTagLengthForCipher($this->cipher) : null;

        return [
            'ivLength' => $ivLength,
            'tagLength' => $tagLength,
            'aad' => (string) $this->aad,
        ];
    }

    /**
     * Encrypts the given data with the specified key.
     * @param string $data The data to be encrypted.
     * @param string $key The key to be used for encryption.
     * 
     * @return string The encrypted data with the authentication tag appended.
     * 
     * @throws HashException If encryption fails.
     */
    private function encryptData(string $data, string $key)
    {
        $options = $this->buildEncryptOptions();
        $iv = openssl_random_pseudo_bytes($options['ivLength']);
        // Initialize tag variable
        $tag = null; // Important for AEAD mode

        $encrypted = openssl_encrypt(
            $data,
            $this->cipher,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $options['aad'], // Provide AAD if applicable
            $options['tagLength']
        );

        if ($encrypted === false) {
            throw new HashException('Encryption failed.');
        }

        // Append tag only if cipher is AEAD
        $tagSuffix = $this->isAEADCipher($this->cipher) && $tag !== null ? $tag : '';

        return $iv . $encrypted . $tagSuffix;
    }

    /**
     * Get the standard tag length for the specified cipher, if applicable.
     * @param string $cipher The cipher method.
     * 
     * @return int|null The tag length, or null if not applicable.
     */
    private function getTagLengthForCipher(string $cipher)
    {
        // This map could be expanded to include tag lengths for other AEAD ciphers
        $cipherTagLengths = [
            'aes-256-gcm' => 16,
            'aes-128-gcm' => 16
        ];

        return $cipherTagLengths[$cipher] ?? null;
    }
    
    /**
     * Check if the cipher is AEAD (Authenticated Encryption with Additional Data) type.
     * @param string $cipher The cipher method.
     * 
     * @return bool Whether the cipher is AEAD or not.
     */
    private function isAEADCipher(string $cipher)
    {
        // List of AEAD ciphers: adjust according to needs
        $aeadCiphers = ['aes-256-gcm', 'aes-128-gcm'];

        return in_array($cipher, $aeadCiphers);
    }

    /**
     * Generate the formatted encrypted path using the provided formatter callback,
     * or revert to a default formatting if no custom formatter has been set.
     * 
     * @param string $encryptedUrl The base64 encoded encrypted URL.
     * 
     * @return string The formatted encrypted path.
     */
    private function formatEncryptedPath(string $encryptedUrl)
    {
        // Options for callback, providing additional customizable parameters as needed
        $options = [
            'prefix' => $this->prefix,
            'suffix' => $this->suffix
        ];

        // Call the user-defined callback if available, providing encryptedUrl and additional options
        if (is_callable($this->pathFormatterCallback)) {
            return call_user_func($this->pathFormatterCallback, $encryptedUrl, $options);
        }

        // Default formatting, applying custom prefix and suffix if they have been set
        $formattedPath = $this->prefix . '/enc/' . rtrim($encryptedUrl, '/') . $this->suffix;

        return rtrim($formattedPath, '/');
    }
}
