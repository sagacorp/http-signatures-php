<?php

namespace HttpSignatures;

interface AsymmetricAlgorithmInterface extends AlgorithmInterface
{
    public function verify(string $message, string $signature, array|string $verifyingKey): bool;
}
