<?php

namespace HttpSignatures;

abstract class Algorithm
{
    /**
     * @throws Exception
     */
    public static function create(string $name): AlgorithmInterface
    {
        return match ($name) {
            'hmac-sha1' => new HmacAlgorithm('sha1'),
            'hmac-sha256' => new HmacAlgorithm('sha256'),
            'rsa-sha1' => new RsaAlgorithm('sha1'),
            'rsa-sha256' => new RsaAlgorithm('sha256'),
            'dsa-sha1' => new DsaAlgorithm('sha1'),
            'dsa-sha256' => new DsaAlgorithm('sha256'),
            'ec-sha1' => new EcAlgorithm('sha1'),
            'ec-sha256' => new EcAlgorithm('sha256'),
            default => throw new AlgorithmException("No algorithm named '$name'"),
        };
    }
}
