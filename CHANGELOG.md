# CHANGELOG

## Unreleased

- Support phpseclib 3 and 4 (`^3.0 || ^4.0.1`).
  - The two releases expose the same classes under different namespaces, so
    `src/Phpseclib/bootstrap.php` aliases whichever one is installed into
    `HttpSignatures\Phpseclib`.
  - `X509` certificate loading branches on the phpseclib version.
- Widen development dependencies so they resolve against the running PHP
  version: PHPUnit `^11.5 || ^12.0 || ^13.0`, guzzlehttp/psr7 `^2.7 || ^3.0`,
  symfony/http-foundation and symfony/psr-http-message-bridge `^7.2 || ^8.0`.
  PHPUnit 13 and Symfony 8 require PHP 8.4, which the library itself does not.
- Replace the Travis configuration with a GitHub Actions matrix covering
  PHP 8.3/8.4/8.5 against lowest and highest dependencies, plus a php-cs-fixer
  job.
- Apply the outstanding php-cs-fixer fixes (`no_useless_else`,
  `statement_indentation`, whitespace); no behaviour changes.

## 11.0.0-beta1

- Move phpseclib from git ref to "stable" liamdennehy/phpseclib.
  - Temporary dependency until phpseclib 3.0 stabilises, avoids having to
    use direct git commit refs and library appears to have "stable" only deps.
  - phpseclib 3.0 is still in development, but API is unlikely to drastically
    change, and once rleeased this dependency will revert to the official
    package (with any required fixes).

## 11.0.0-alpha3

- Remove all openssl depedencencies
  - Functionality becomes tied to whatever version of openssl libraries
    are compiled into PHP, leading to difficulty predicting which ciphers
    are supported
  - OpenSSL functions are difficult to use with very different bahaviour (e.g.
    little consistency on exceptions vs silent failure, some functions returning
    vaues while other place return values in parameters)
- phpseclib for all crypto functions
  - phpselcib 3.0 not yet stable so pull directly from master
- Key class behaviour altered (interface remains same)
  - Asymmetric: Only permit one private key, and only return one signing key.
    Exception at creation for early failure.
