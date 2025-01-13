<?php

namespace HttpSignatures;

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;

readonly class RsaAlgorithm implements AsymmetricAlgorithmInterface
{
    public function __construct(private string $digestName)
    {
    }

    public function name(): string
    {
        return sprintf('rsa-%s', $this->digestName);
    }

    public function sign(string $key, string $data): string
    {
        /** @var RSA\PrivateKey $rsa */
        $rsa = PublicKeyLoader::load($key)->withHash($this->digestName);
        $rsa = $rsa->withPadding(RSA::SIGNATURE_PKCS1);

        return $rsa->sign($data);
    }

    /**
     * @throws \Exception
     */
    public function verify(string $message, string $signature, array|string $verifyingKey): bool
    {
        /** @var RSA\PublicKey $rsa */
        $rsa = PublicKeyLoader::load($verifyingKey)->withHash($this->digestName);
        $rsa = $rsa->withPadding(RSA::SIGNATURE_PKCS1);

        try {
            return $rsa->verify($message, base64_decode($signature));
        } catch (\Exception $e) {
            if ('Invalid signature' != $e->getMessage()) {
                // Unhandled error state
                throw $e;
            } else {
                // Tolerate malformed signature
                return false;
            }
        }
    }
}
