<?php

namespace HttpSignatures;

use Psr\Http\Message\RequestInterface;

class Verification
{
    private array $parameters;

    /**
     * @throws SignatureParseException
     * @throws HeaderException
     */
    public function __construct(private readonly RequestInterface $message, private readonly KeyStoreInterface $keyStore, private readonly string $header)
    {
        // TODO: Find one signature line within multiple header instances
        // This will permit e.g. Authorization: Bearer to co-exist with Authorization: Signature
        switch (strtolower($header)) {
            case 'signature':
                if (0 == sizeof($message->getHeader('Signature'))) {
                    throw new HeaderException("Cannot locate header 'Signature'");
                } elseif (sizeof($message->getHeader('Signature')) > 1) {
                    throw new HeaderException("Multiple headers named 'Signature'");
                }
                $signatureLine = $message->getHeader('Signature')[0];
                break;
            case 'authorization':
                if (0 == sizeof($message->getHeader('Authorization'))) {
                    throw new HeaderException("Cannot locate header 'Authorization'");
                } elseif (sizeof($message->getHeader('Authorization')) > 1) {
                    throw new HeaderException("Multiple headers named 'Authorization'");
                }
                $authorizationType = explode(' ', $message->getHeader('Authorization')[0])[0];
                if ('Signature' == $authorizationType) {
                    $signatureLine = substr($message->getHeader('Authorization')[0], strlen('Signature '));
                } else {
                    throw new HeaderException("Unknown Authorization type $authorizationType, cannot verify");
                }
                break;
            default:
                throw new HeaderException("Unknown header type '".$header."', cannot verify");
        }
        $signatureParametersParser = new SignatureParametersParser($signatureLine);
        $this->parameters = $signatureParametersParser->parse();
    }

    /**
     * @throws KeyStoreException
     * @throws KeyException
     * @throws SignatureException
     * @throws SignedHeaderNotPresentException
     * @throws Exception
     */
    public function verify(): bool
    {
        try {
            $key = $this->key();
            switch ($key->getClass()) {
                case 'secret':
                    if (hash_equals(
                        $this->expectedSignature()->string(),
                        $this->providedSignature()
                    )) {
                        return true;
                    } else {
                        throw new SignatureException('Invalid signature', 1);
                    }
                    break;
                case 'asymmetric':
                    $signedString = new SigningString(
                        $this->headerList(),
                        $this->message
                    );
                    /** @var AsymmetricAlgorithmInterface $algorithm */
                    $algorithm = Algorithm::create($this->parameter('algorithm'));

                    return $algorithm->verify(
                        $signedString->string(),
                        $this->parameter('signature'),
                        $key->getVerifyingKey());
                default:
                    throw new Exception("Unknown key type '".$key->getType()."', cannot verify");
            }
            // } catch (SignatureParseException $e) {
            //     return false;
        } catch (KeyStoreException) {
            throw new KeyStoreException("Cannot locate key for supplied keyId '{$this->parameter('keyId')}'", 1);
            // return false;
            // } catch (SignedHeaderNotPresentException $e) {
            //     return false;
        }
    }

    /**
     * @throws Exception
     */
    private function expectedSignature(): Signature
    {
        return new Signature(
            $this->message,
            $this->keyId(),
            $this->algorithm(),
            $this->headerList()
        );
    }

    /**
     * @throws Exception
     */
    private function providedSignature(): string
    {
        return base64_decode($this->headerParameter('signature'));
    }

    /**
     * @throws Exception
     */
    private function keyId(): Key
    {
        return $this->keyStore->fetch($this->headerParameter('keyId'));
    }

    /**
     * @throws Exception
     */
    private function algorithm(): AlgorithmInterface
    {
        return Algorithm::create($this->headerParameter('algorithm'));
    }

    /**
     * @throws Exception
     */
    private function headerParameter(string $name): string
    {
        // $headerParameters = $this->headerParameters();
        if (!isset($this->parameters[$name])) {
            throw new Exception("'$this->header' header parameters does not contain '$name'");
        }

        return $this->parameters[$name];
    }

    /**
     * @throws Exception
     */
    private function key(): Key
    {
        return $this->keyStore->fetch($this->parameter('keyId'));
    }

    /**
     * @throws Exception
     */
    private function parameter(string $name): string
    {
        // $parameters = $this->parameters();
        if (!isset($this->parameters[$name])) {
            if ('headers' == $name) {
                return 'date';
            } else {
                throw new Exception("Signature parameters does not contain '$name'");
            }
        }

        return $this->parameters[$name];
    }

    /**
     * @throws Exception
     */
    private function headerList(): HeaderList
    {
        return HeaderList::fromString($this->parameter('headers'));
    }

    /**
     * @throws SignedHeaderNotPresentException
     * @throws Exception
     */
    public function getSigningString(): string
    {
        $signedString = new SigningString(
            $this->headerList(),
            $this->message
        );

        return $signedString->string();
    }
}
