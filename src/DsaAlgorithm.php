<?php

namespace HttpSignatures;

use phpseclib3\Crypt\DSA;
use phpseclib3\Crypt\PublicKeyLoader;

readonly class DsaAlgorithm implements AsymmetricAlgorithmInterface
{
    public function __construct(private string $digestName)
    {
    }

    public function name(): string
    {
        return sprintf('dsa-%s', $this->digestName);
    }

    public function sign(string $key, string $data): string
    {
        /** @var DSA\PrivateKey $dsa */
        $dsa = PublicKeyLoader::load($key)->withHash($this->digestName);

        return $dsa->sign($data);
    }

    public function verify(string $message, string $signature, array|string $verifyingKey): bool
    {
        /** @var DSA\PublicKey $dsa */
        $dsa = PublicKeyLoader::load($verifyingKey)->withHash($this->digestName);

        try {
            return $dsa->verify($message, base64_decode($signature));
        } catch (\Exception) {
            // Tolerate malformed signature
            return false;
        }
    }
}
