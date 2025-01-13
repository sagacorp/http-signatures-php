<?php

namespace HttpSignatures;

class Context
{
    private array $headers;
    private KeyStoreInterface $keyStore;
    private string $signingKeyId;
    public ?AlgorithmInterface $algorithm = null;

    /**
     * @throws Exception
     */
    public function __construct(array $args)
    {
        if (isset($args['keys'], $args['keyStore'])) {
            throw new Exception(__CLASS__.' accepts keys or keyStore but not both');
        } elseif (isset($args['keys'])) {
            // array of keyId => keySecret
            $this->setKeyStore(new KeyStore($args['keys']));
        } elseif (isset($args['keyStore'])) {
            $this->setKeyStore($args['keyStore']);
        }

        // algorithm for signing; not necessary for verifying.
        if (isset($args['algorithm'])) {
            $this->algorithm = Algorithm::create($args['algorithm']);
        }
        // headers list for signing; not necessary for verifying.
        if (isset($args['headers'])) {
            $this->headers = $args['headers'];
        }

        // signingKeyId specifies the key used for signing messages.
        if (isset($args['signingKeyId'])) {
            $this->signingKeyId = $args['signingKeyId'];
        } elseif (isset($args['keys']) && 1 === count($args['keys'])) {
            list($this->signingKeyId) = array_keys($args['keys']); // first key
        }
    }

    /**
     * @throws Exception
     */
    public function signer(): Signer
    {
        return new Signer(
            $this->signingKey(),
            $this->algorithm(),
            $this->headerList()
        );
    }

    public function verifier(): Verifier
    {
        return new Verifier($this->keyStore());
    }

    /**
     * @throws Exception
     * @throws KeyStoreException
     */
    private function signingKey(): Key
    {
        if (isset($this->signingKeyId)) {
            return $this->keyStore()->fetch($this->signingKeyId);
        } else {
            throw new Exception('no implicit or specified signing key');
        }
    }

    private function headerList(): HeaderList
    {
        if (isset($this->headers)) {
            return new HeaderList($this->headers, true);
        } else {
            return new HeaderList(['date'], false);
        }
    }

    private function keyStore(): KeyStoreInterface
    {
        return $this->keyStore;
    }

    private function setKeyStore(KeyStoreInterface $keyStore): void
    {
        $this->keyStore = $keyStore;
    }

    private function algorithm(): ?AlgorithmInterface
    {
        return $this->algorithm;
    }
}
