<?php

namespace HttpSignatures;

use Psr\Http\Message\RequestInterface;

readonly class SigningString
{
    public function __construct(private HeaderList $headerList, private RequestInterface $message)
    {
    }

    /**
     * @throws SignedHeaderNotPresentException
     */
    public function string(): string
    {
        return implode("\n", $this->lines());
    }

    /**
     * @throws SignedHeaderNotPresentException
     */
    private function lines(): array
    {
        return is_null($this->headerList->names)
            ? []
            : array_map(
                fn (string $headerName) => $this->line($headerName),
                $this->headerList->names
            );
    }

    /**
     * @throws SignedHeaderNotPresentException
     */
    private function line(string $headerName): string
    {
        return '(request-target)' == $headerName
            ? $this->requestTargetLine()
            : sprintf('%s: %s', $headerName, $this->headerValue($headerName));
    }

    /**
     * @throws SignedHeaderNotPresentException
     */
    private function headerValue(string $name): string
    {
        if (!$this->message->hasHeader($name)) {
            throw new SignedHeaderNotPresentException("Header '$name' not in message");
        }

        $header = '';
        $values = $this->message->getHeader($name);
        while (count($values) > 0) {
            $header = $header.$values[0];
            array_shift($values);
            if (count($values) > 0) {
                $header = $header.', ';
            }
        }

        // $header = $this->message->getHeader($name);

        return $header;
        // return end($header);
    }

    private function requestTargetLine(): string
    {
        return sprintf(
            '(request-target): %s %s',
            strtolower($this->message->getMethod()),
            $this->message->getRequestTarget()
        );
    }
}
