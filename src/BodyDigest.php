<?php

namespace HttpSignatures;

use Psr\Http\Message\RequestInterface;

class BodyDigest
{
    public const string validHashes = 'sha sha1 sha256 sha512';

    private string $hashName;

    private string $digestHeaderPrefix;

    /**
     * @throws DigestException
     */
    public function __construct(?string $hashAlgorithm = null)
    {
        // Default to sha256 if no spec provided
        if (empty($hashAlgorithm)) {
            $hashAlgorithm = 'sha256';
        }

        $hashAlgorithm = strtolower(str_replace('-', '', $hashAlgorithm));
        if (!$this->isValidDigestSpec($hashAlgorithm)) {
            throw new DigestException("'$hashAlgorithm' is not a valid Digest algorithm specifier");
        }
        switch ($hashAlgorithm) {
            case 'sha':
            case 'sha1':
                $this->hashName = 'sha1';
                $this->digestHeaderPrefix = 'SHA';
                break;
            case 'sha256':
                $this->hashName = 'sha256';
                $this->digestHeaderPrefix = 'SHA-256';
                break;
            case 'sha512':
                $this->hashName = 'sha512';
                $this->digestHeaderPrefix = 'SHA-512';
                break;
        }
    }

    public function putDigestInHeaderList(HeaderList $headerList): HeaderList
    {
        if (!array_search('digest', $headerList->names)) {
            $headerList->names[] = 'digest';
        }

        return $headerList;
    }

    public function setDigestHeader(RequestInterface $message): RequestInterface
    {
        return $message->withoutHeader('Digest')
            ->withHeader(
                'Digest',
                $this->getDigestHeaderLineFromBody($message->getBody())
            );
    }

    public function getDigestHeaderLineFromBody(?string $messageBody): string
    {
        if (is_null($messageBody)) {
            $messageBody = '';
        }

        return $this->digestHeaderPrefix.'='.base64_encode(hash($this->hashName, $messageBody, true));
    }

    /**
     * @throws DigestException
     */
    public static function fromMessage(RequestInterface $message): BodyDigest
    {
        $digestLine = $message->getHeader('Digest');
        if (!$digestLine) {
            throw new DigestException('No Digest header in message');
        }

        $digestAlgorithm = self::getDigestAlgorithm($digestLine[0]);

        return new BodyDigest($digestAlgorithm);
    }

    /**
     * @throws DigestException
     */
    private static function getDigestAlgorithm(string $digestLine): string
    {
        // simple test if properly delimited, but see below
        if (!strpos($digestLine, '=')) {
            throw new DigestException('Digest header does not appear to be correctly formatted');
        }

        // '=' is valid base64, so raw base64 may match
        $hashAlgorithm = explode('=', $digestLine)[0];
        if (!self::isValidDigestSpec($hashAlgorithm)) {
            throw new DigestException("'$hashAlgorithm' in Digest header is not a valid algorithm");
        }

        return $hashAlgorithm;
    }

    public function isValid(RequestInterface $message): bool
    {
        $receivedDigest = $message->getHeader('Digest')[0];
        $expectedDigest = $this->getDigestHeaderLineFromBody($message->getBody());

        return hash_equals($receivedDigest, $expectedDigest);
    }

    public static function isValidDigestSpec(string $digestSpec): bool
    {
        $digestSpec = strtolower(str_replace('-', '', $digestSpec));
        $validHashes = explode(' ', self::validHashes);

        return in_array($digestSpec, $validHashes);
    }
}
