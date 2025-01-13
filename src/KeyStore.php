<?php

namespace HttpSignatures;

class KeyStore implements KeyStoreInterface
{
    /** @var Key[] */
    private array $keys;

    /**
     * @throws KeyException
     */
    public function __construct(array $keys)
    {
        $this->keys = [];
        foreach ($keys as $id => $key) {
            $this->keys[$id] = new Key($id, $key);
        }
    }

    /**
     * @throws KeyStoreException
     */
    public function fetch(string $keyId): Key
    {
        if (isset($this->keys[$keyId])) {
            return $this->keys[$keyId];
        } else {
            throw new KeyStoreException("Key '$keyId' not found");
        }
    }
}
