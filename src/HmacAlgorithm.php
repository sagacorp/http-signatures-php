<?php

namespace HttpSignatures;

readonly class HmacAlgorithm implements AlgorithmInterface
{
    public function __construct(private string $digestName)
    {
    }

    public function name(): string
    {
        return sprintf('hmac-%s', $this->digestName);
    }

    public function sign(string $key, string $data): string
    {
        return hash_hmac($this->digestName, $data, $key, true);
    }
}
