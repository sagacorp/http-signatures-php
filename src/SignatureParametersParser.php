<?php

namespace HttpSignatures;

readonly class SignatureParametersParser
{
    public function __construct(private string $input)
    {
    }

    /**
     * @throws SignatureParseException
     */
    public function parse(): array
    {
        $result = $this->pairsToAssociative(
            $this->arrayOfPairs()
        );
        $this->validate($result);

        return $result;
    }

    private function pairsToAssociative(array $pairs): array
    {
        $result = [];
        foreach ($pairs as $pair) {
            $result[$pair[0]] = $pair[1];
        }

        return $result;
    }

    /**
     * @throws SignatureParseException
     */
    private function arrayOfPairs(): array
    {
        return array_map(fn (string $segment) => $this->pair($segment), $this->segments());
    }

    private function segments(): array
    {
        return explode(',', $this->input);
    }

    /**
     * @throws SignatureParseException
     */
    private function pair(string $segment): array
    {
        $segmentPattern = '/\A(keyId|algorithm|headers|signature)="(.*)"\z/';
        $matches = [];
        $result = preg_match($segmentPattern, $segment, $matches);
        if (1 !== $result) {
            // TODO: This is not strictly required, unknown parameters should be ignored
            // @see https://tools.ietf.org/html/draft-cavage-http-signatures-10#section-2.2
            throw new SignatureParseException("Signature parameters segment '$segment' invalid");
        }
        array_shift($matches);

        return $matches;
    }

    /**
     * @throws SignatureParseException
     */
    private function validate(array $result): void
    {
        $this->validateAllKeysArePresent($result);
    }

    /**
     * @throws SignatureParseException
     */
    private function validateAllKeysArePresent(array $result): void
    {
        // Regexp in pair() ensures no unwanted keys exist.
        // Ensure that all mandatory keys exist.
        $wanted = ['keyId', 'algorithm', 'signature'];
        $missing = array_diff($wanted, array_keys($result));
        if (!empty($missing)) {
            $csv = implode(', ', $missing);
            throw new SignatureParseException("Missing keys $csv");
        }
    }
}
