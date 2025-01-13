<?php

namespace HttpSignatures;

class HeaderList
{
    public array $names;

    private bool $headerListSpecified;

    public function __construct(?array $names, bool $headerListSpecified = true)
    {
        if ($names) {
            $this->names = array_map(fn (string $name) => $this->normalize($name), $names);
            $this->headerListSpecified = $headerListSpecified;
        } else {
            $this->names = [];
            $this->headerListSpecified = false;
        }
    }

    public static function fromString(string $string): HeaderList
    {
        return new static(explode(' ', $string));
    }

    public function string(): string
    {
        return implode(' ', $this->names);
    }

    public function headerListSpecified(): bool
    {
        return $this->headerListSpecified;
    }

    private function normalize(string $name): string
    {
        return strtolower($name);
    }
}
