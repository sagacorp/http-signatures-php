<?php

namespace HttpSignatures\tests;

use HttpSignatures\HeaderList;
use HttpSignatures\HmacAlgorithm;
use HttpSignatures\Key;
use HttpSignatures\RsaAlgorithm;
use HttpSignatures\SignatureParameters;
use PHPUnit\Framework\TestCase;

class SignatureParametersTest extends TestCase
{
    public function testHmacToString()
    {
        $key = new Key('pda', 'secret');
        $algorithm = new HmacAlgorithm('sha256');
        $headerList = new HeaderList(['(request-target)', 'date']);

        $signature = $this->getMockBuilder('HttpSignatures\Signature')
            ->disableOriginalConstructor()
            ->getMock();

        $signature
            ->expects($this->any())
            ->method('string')
            ->willReturn('thesignature');

        $sp = new SignatureParameters($key, $algorithm, $headerList, $signature);

        $this->assertEquals(
            'keyId="pda",algorithm="hmac-sha256",headers="(request-target) date",signature="dGhlc2lnbmF0dXJl"',
            $sp->string()
        );
    }

    public function testRsaToString()
    {
        $key = new Key('pda', TestKeys::rsaPrivateKey);
        $algorithm = new RsaAlgorithm('sha256');
        $headerList = new HeaderList(['(request-target)', 'date']);

        $signature = $this->getMockBuilder('HttpSignatures\Signature')
            ->disableOriginalConstructor()
            ->getMock();

        $signature
            ->expects($this->any())
            ->method('string')
            ->willReturn('thesignature');

        $sp = new SignatureParameters($key, $algorithm, $headerList, $signature);

        $this->assertEquals(
            'keyId="pda",algorithm="rsa-sha256",headers="(request-target) date",signature="dGhlc2lnbmF0dXJl"',
            $sp->string()
        );
    }
}
