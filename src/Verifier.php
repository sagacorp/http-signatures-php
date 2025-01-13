<?php

namespace HttpSignatures;

use Psr\Http\Message\RequestInterface;

class Verifier
{
    private array $status = [];

    public function __construct(private readonly KeyStoreInterface $keyStore)
    {
    }

    /**
     * @throws Exception
     */
    public function isSigned(RequestInterface $message): bool
    {
        $this->status = [];
        try {
            $verification = new Verification($message, $this->keyStore, 'Signature');
            $result = $verification->verify();
            $this->status[] =
              "Message SigningString: '".
              base64_encode($verification->getSigningString()).
              "'";

            return $result;
        } catch (Exception $e) {
            // TODO: Match at least one header
            switch (get_class($e)) {
                case 'HttpSignatures\HeaderException':
                    $this->status[] = 'Signature header not found';

                    return false;
                case 'HttpSignatures\SignatureParseException':
                    $this->status[] = 'Signature header malformed';

                    return false;
                case 'HttpSignatures\SignedHeaderNotPresentException':
                case 'HttpSignatures\KeyStoreException':
                case 'HttpSignatures\SignatureException':
                    $this->status[] = $e->getMessage();

                    return false;
                default:
                    $this->status[] = 'Unknown exception '.get_class($e).': '.$e->getMessage();
                    throw $e;
            }
        }
    }

    /**
     * @throws Exception
     */
    public function isAuthorized(RequestInterface $message): bool
    {
        $this->status = [];
        try {
            $verification = new Verification($message, $this->keyStore, 'Authorization');
            $result = $verification->verify();
            $this->status[] =
              "Message SigningString: '".
              base64_encode($verification->getSigningString()).
              "'";

            return $result;
        } catch (Exception $e) {
            // TODO: Match at least one header
            switch (get_class($e)) {
                case 'HttpSignatures\HeaderException':
                    $this->status[] = 'Authorization header not found';

                    return false;
                case 'HttpSignatures\SignatureParseException':
                    $this->status[] = 'Authorization header malformed';

                    return false;
                default:
                    $this->status[] = 'Unknown exception '.get_class($e).': '.$e->getMessage();
                    throw $e;
            }
        }
    }

    public function isValidDigest(RequestInterface $message): bool
    {
        $this->status = [];
        if (0 == sizeof($message->getHeader('Digest'))) {
            $this->status[] = 'Digest header mising';

            return false;
        }
        try {
            $bodyDigest = BodyDigest::fromMessage($message);
        } catch (DigestException $e) {
            $this->status[] = $e->getMessage();

            return false;
        }

        $isValidDigest = $bodyDigest->isValid($message);
        if (!$isValidDigest) {
            $this->status[] = 'Digest header invalid';
        }

        return $isValidDigest;
    }

    /**
     * @throws Exception
     */
    public function isSignedWithDigest(RequestInterface $message): bool
    {
        if ($this->isValidDigest($message)) {
            if ($this->isSigned($message)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @throws Exception
     */
    public function isAuthorizedWithDigest(RequestInterface $message): bool
    {
        if ($this->isValidDigest($message)) {
            if ($this->isAuthorized($message)) {
                return true;
            }
        }

        return false;
    }

    public function keyStore(): KeyStoreInterface
    {
        return $this->keyStore;
    }

    public function getStatus(): array
    {
        return $this->status;
    }
}
