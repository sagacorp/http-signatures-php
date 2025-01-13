<?php

namespace HttpSignatures;

use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\File\X509;

class Key
{
    private ?AsymmetricKey $privateKey;
    public string $algorithm;

    /** @var AsymmetricKey[] */
    public array $publicKeys;
    public string $curve;

    /** @var string[] */
    public array $secrets;
    public string $class;

    /**
     * @throws KeyException
     */
    public function __construct(private readonly string $id, array|string $keys)
    {
        if (empty($keys)) {
            throw new KeyException('No Key(s) provided', 1);
        }
        $publicKeys = [];
        $privateKey = null;
        $secrets = [];
        if (!is_array($keys)) {
            $keys = [$keys];
        }
        foreach ($keys as $key) {
            try {
                $pkiKey = PublicKeyLoader::load($key);
            } catch (\Exception) {
                $pkiKey = null;
            }

            if (empty($pkiKey)) {
                if (0 != strpos($key, 'BEGIN')) {
                    throw new KeyException('Input looks like PEM but key not understood using phpseclib3', 1);
                } elseif (!empty($publicKeys) || !empty($privateKsy)) {
                    throw new KeyException('PKI Key(s) and Secret provided, only one type of key supported', 1);
                } else {
                    $secrets[hash('sha256', $key)] = $key;
                }
            } else {
                $type = explode('\\', get_class($pkiKey))[3];
                switch ($type) {
                    case 'PrivateKey':
                        if (!empty($privateKey)) {
                            throw new KeyException('Multiple Private Keys Provided, only one signing key supported', 1);
                        }
                        if (!empty($secrets)) {
                            throw new KeyException('Private Key and Secret provided, only one type of signing key supported', 1);
                        }
                        $fingerPrint = hash('sha256', $pkiKey->getPublicKey()->toString('PKCS8'));
                        $privateKey = $pkiKey;
                        $publicKeys[$fingerPrint] = $pkiKey->getPublicKey();
                        break;
                    case 'PublicKey':
                        $fingerPrint = hash('sha256', $pkiKey->toString('PKCS8'));
                        if (!empty($secrets)) {
                            throw new KeyException('Public Key and Secret provided, only one type of verifying key supported', 1);
                        } elseif (!empty($privateKey) && !array_key_exists($fingerPrint, $publicKeys)) {
                            throw new KeyException("Public Key and Private Key don't seem to be related", 1);
                        } else {
                            $publicKeys[$fingerPrint] = $pkiKey;
                        }
                        break;

                    default:
                        throw new KeyException('Something went terribly wrong, not a secret and not PKI - should never happen', 1);
                }
            }
        }
        if (empty($publicKeys)) {
            $this->algorithm = 'HMAC';
            $this->secrets = $secrets;
        } else {
            $this->privateKey = $privateKey;
            $this->publicKeys = $publicKeys;
            $this->algorithm = explode('\\', get_class($pkiKey))[2];
            if ('EC' == $this->algorithm) {
                $this->curve = current($publicKeys)->getCurve();
            }
        }
    }

    /**
     * Retrieves public key resource from a input string.
     */
    private static function getPublicKey(array|string $candidate): ?AsymmetricKey
    {
        try {
            return PublicKeyLoader::load($candidate);
        } catch (\Exception) {
            return null;
        }
    }

    public static function fromX509Certificate(array|string $certificate): ?AsymmetricKey
    {
        return Key::getPublicKey($certificate);
    }

    /**
     * Signing HTTP Messages 'keyId' field.
     */
    public function getId(): string
    {
        return $this->id;
    }

    /**
     * Retrieve Verifying Key - Public Key for Asymmetric/PKI, or shared secret for HMAC.
     *
     * @throws KeyException
     */
    public function getVerifyingKey(string $format = 'PKCS8'): string
    {
        switch ($this->getClass()) {
            case 'asymmetric':
                if (1 != count($this->publicKeys)) {
                    throw new KeyException('More than one Verifying Key. Use getVerifyingKeys() instead', 1);
                // TODO: Implement getVerifyingKeys and multiple key verification
                // https://github.com/liamdennehy/http-signatures-php/issues/20
                } else {
                    return str_replace("\r\n", "\n", current($this->publicKeys)->toString($format));
                }
                // no break
            case 'secret':
                if (1 != count($this->secrets)) {
                    throw new KeyException('More than one Secret Key. Use getVerifyingKeys() instead', 1);
                } else {
                    return current($this->secrets);
                }
                // no break
            default:
                throw new KeyException("Unknown key class $this->class");
        }
    }

    /**
     * Retrieve Signing Key - Private Key for Asymmetric/PKI, or shared secret for HMAC.
     *
     * @throws KeyException
     */
    public function getSigningKey(string $format = 'PKCS8'): ?string
    {
        return match ($this->getClass()) {
            'asymmetric' => empty($this->privateKey)
                ? null
                : str_replace("\r\n", "\n", $this->privateKey->toString($format)),
            'secret' => count($this->secrets) <= 1
                ? current($this->secrets)
                : throw new KeyException('Multiple Secrets in Key, use only one as input for signing'),
            default => throw new KeyException("Unknown key class $this->class"),
        };
    }

    public function getClass(): string
    {
        return empty($this->publicKeys) ? 'secret' : 'asymmetric';
    }

    /**
     * @throws KeyException
     */
    public function getType(): string
    {
        return match ($this->getClass()) {
            'secret' => 'hmac',
            'asymmetric' => strtolower($this->algorithm),
            default => throw new KeyException("Unknown key class '{$this->class}' fetching algorithm", 1),
        };
    }

    public function getCurve(): string
    {
        return $this->curve;
    }

    public static function isX509Certificate(array|string $candidate): bool
    {
        try {
            $x509 = new X509();
            $x509->loadX509($candidate);
            $key = $x509->getPublicKey();

            return (bool) $key;
        } catch (\Exception) {
            return false;
        }
    }

    public static function isPublicKey(array|string $object): bool
    {
        return Key::hasPublicKey($object)
               && !Key::hasPrivateKey($object)
               && !Key::isX509Certificate($object);
    }

    public static function isPrivateKey(array|string $object): bool
    {
        return Key::hasPrivateKey($object)
               && !Key::isPublicKey($object);
    }

    public static function hasPKIKey(array|string $item): bool
    {
        return Key::hasPublicKey($item)
               || Key::hasPrivateKey($item);
    }

    public static function hasPublicKey(array|string $candidate)
    {
        if (empty($candidate)) {
            return false;
        }

        if (is_string($candidate)) {
            try {
                $key = PublicKeyLoader::load($candidate);
                if (empty($key)) {
                    return false;
                }
                if ($key instanceof PrivateKey) {
                    $key = $key->getPublicKey();
                    if (empty($key)) {
                        return false;
                    }
                }

                return 'PublicKey' === explode('\\', get_class($key))[3];
            } catch (\Exception) {
                return false;
            }
        }
    }

    /**
     * Test if $object is, points to or contains, PEM-format Private Key.
     */
    public static function hasPrivateKey(string|array $candidate): bool
    {
        if (empty($candidate)) {
            return false;
        } elseif (is_string($candidate)) {
            try {
                $key = PublicKeyLoader::load($candidate);
                if (empty($key)) {
                    return false;
                }

                return $key instanceof PrivateKey;
            } catch (\Exception) {
                return false;
            }
        }
    }

    public static function isPKIKey(array|string $item): bool
    {
        return Key::isPrivateKey($item)
               || Key::isPublicKey($item);
    }
}
