<?php

namespace HttpSignatures;

use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\PublicKeyLoader;

readonly class EcAlgorithm implements AsymmetricAlgorithmInterface
{
    public function __construct(private string $digestName)
    {
    }

    public function name(): string
    {
        return sprintf('ec-%s', $this->digestName);
    }

    public function sign(string $key, string $data): string
    {
        /** @var EC\PrivateKey $ec */
        $ec = PublicKeyLoader::load($key)->withHash($this->digestName);

        return $ec->sign($data);
    }

    public function verify(string $message, string $signature, array|string $verifyingKey): bool
    {
        /** @var EC\PublicKey $ec */
        $ec = PublicKeyLoader::load($verifyingKey)->withHash($this->digestName);

        try {
            return $ec->verify($message, base64_decode($signature));
        } catch (\Exception) {
            // Tolerate malformed signature
            return false;
        }
    }
}
