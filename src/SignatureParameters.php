<?php

namespace HttpSignatures;

readonly class SignatureParameters
{
    public function __construct(
        private Key $key,
        private AlgorithmInterface $algorithm,
        private HeaderList $headerList,
        private Signature $signature,
    ) {
    }

    /**
     * @throws KeyException
     */
    public function string(): string
    {
        return implode(',', $this->parameterComponents());
    }

    /**
     * @throws KeyException
     */
    private function parameterComponents(): array
    {
        $components = [];
        $components[] = sprintf('keyId="%s"', $this->key->getId());
        $components[] = sprintf('algorithm="%s"', $this->algorithm->name());
        if ($this->headerList->headerListSpecified()) {
            $components[] = sprintf('headers="%s"', $this->headerList->string());
        }
        $components[] = sprintf('signature="%s"', $this->signatureBase64());

        return $components;
    }

    /**
     * @throws KeyException
     */
    private function signatureBase64(): string
    {
        return base64_encode($this->signature->string());
    }
}
