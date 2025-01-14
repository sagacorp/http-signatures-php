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
            if ($result) {
                $this->status[] = "Message SigningString: '".base64_encode($verification->getSigningString())."'";
            }

            return $result;
        } catch (HeaderException) {
            $this->status[] = 'Signature header not found';
        } catch (SignatureParseException) {
            $this->status[] = 'Signature header malformed';
        } catch (SignedHeaderNotPresentException|KeyStoreException|SignatureException $e) {
            $this->status[] = $e->getMessage();
        } catch (Exception $e) {
            $this->status[] = 'Unknown exception '.get_class($e).': '.$e->getMessage();

            throw $e;
        }

        return false;
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
            if ($result) {
                $this->status[] = "Message SigningString: '".base64_encode($verification->getSigningString())."'";
            }

            return $result;
        } catch (HeaderException) {
            $this->status[] = 'Authorization header not found';
        } catch (SignatureParseException) {
            $this->status[] = 'Authorization header malformed';
        } catch (Exception $e) {
            $this->status[] = 'Unknown exception '.get_class($e).': '.$e->getMessage();

            throw $e;
        }

        return false;
    }

    public function isValidDigest(RequestInterface $message): bool
    {
        $this->status = [];
        if (0 == count($message->getHeader('Digest'))) {
            $this->status[] = 'Digest header not found';

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
