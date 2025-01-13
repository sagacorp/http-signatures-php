<?php

namespace HttpSignatures;

interface AlgorithmInterface
{
    public function name(): string;

    public function sign(string $key, string $data): string;
}
