<?php

namespace HttpSignatures;

use Psr\Http\Message\RequestInterface;

class Signature
{
    private SigningString $signingString;

    public function __construct(RequestInterface $message, private readonly Key $key, private readonly AlgorithmInterface $algorithm, HeaderList $headerList)
    {
        $this->signingString = new SigningString($headerList, $message);
    }

    /**
     * @throws KeyException
     */
    public function string(): string
    {
        return $this->algorithm->sign(
            $this->key->getSigningKey(),
            $this->signingString->string()
        );
    }
}
