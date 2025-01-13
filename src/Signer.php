<?php

namespace HttpSignatures;

use Psr\Http\Message\RequestInterface;

class Signer
{
    public function __construct(private readonly Key $key, private readonly ?AlgorithmInterface $algorithm, private HeaderList $headerList)
    {
    }

    /**
     * @throws KeyException
     */
    public function sign(RequestInterface $message): RequestInterface
    {
        $signatureParameters = $this->signatureParameters($message);

        return $message->withAddedHeader('Signature', $signatureParameters->string());
    }

    /**
     * @throws KeyException
     */
    public function authorize(RequestInterface $message): RequestInterface
    {
        $signatureParameters = $this->signatureParameters($message);

        return $message->withAddedHeader('Authorization', 'Signature '.$signatureParameters->string());
    }

    /**
     * @throws KeyException
     */
    public function signWithDigest(RequestInterface $message): RequestInterface
    {
        $bodyDigest = new BodyDigest();
        $this->headerList = $bodyDigest->putDigestInHeaderList($this->headerList);

        return $this->sign($bodyDigest->setDigestHeader($message));
    }

    /**
     * @throws KeyException
     */
    public function authorizeWithDigest(RequestInterface $message): RequestInterface
    {
        $bodyDigest = new BodyDigest();
        $this->headerList = $bodyDigest->putDigestInHeaderList($this->headerList);

        return $this->authorize($bodyDigest->setDigestHeader($message));
    }

    private function signatureParameters(RequestInterface $message): SignatureParameters
    {
        return new SignatureParameters(
            $this->key,
            $this->algorithm,
            $this->headerList,
            $this->signature($message)
        );
    }

    private function signature(RequestInterface $message): Signature
    {
        return new Signature(
            $message,
            $this->key,
            $this->algorithm,
            $this->headerList
        );
    }

    public function getSigningString($message): string
    {
        $singingString = new SigningString($this->headerList, $message);

        return $singingString->string();
    }
}
