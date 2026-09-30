<?php

/*
 * phpseclib 3 and 4 expose the same classes under different namespaces
 * (phpseclib3\ and phpseclib4\). Alias whichever one is installed into
 * HttpSignatures\Phpseclib so the rest of the library has a single set of
 * names to import.
 */

$httpSignaturesPhpseclib = class_exists('phpseclib4\\Crypt\\PublicKeyLoader')
    ? 'phpseclib4'
    : 'phpseclib3';

foreach ([
    'Crypt\Common\AsymmetricKey',
    'Crypt\Common\PrivateKey',
    'Crypt\DSA',
    'Crypt\EC',
    'Crypt\PublicKeyLoader',
    'Crypt\RSA',
    'File\X509',
] as $httpSignaturesClass) {
    class_alias(
        $httpSignaturesPhpseclib.'\\'.$httpSignaturesClass,
        'HttpSignatures\\Phpseclib\\'.substr($httpSignaturesClass, strrpos($httpSignaturesClass, '\\') + 1)
    );
}

unset($httpSignaturesPhpseclib, $httpSignaturesClass);
