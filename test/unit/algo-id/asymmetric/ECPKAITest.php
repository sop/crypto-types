<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 *
 * @internal
 */
class ECPKAITest extends TestCase
{
    const OID = '1.2.840.10045.3.1.7';

    /**
     * @return Sequence
     */
    public function testEncode()
    {
        $ai = new ECPublicKeyAlgorithmIdentifier(self::OID);
        $seq = $ai->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    /**
     * @depends testEncode
     *
     * @param Sequence $seq
     */
    public function testDecode(Sequence $seq)
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        $this->assertInstanceOf(ECPublicKeyAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends testEncode
     *
     * @param Sequence $seq
     */
    public function testDecodeNoParamsFail(Sequence $seq)
    {
        $seq = $seq->withoutElement(1);
        $this->expectException(\UnexpectedValueException::class);
        AlgorithmIdentifier::fromASN1($seq);
    }

    /**
     * @depends testDecode
     *
     * @param ECPublicKeyAlgorithmIdentifier $ai
     */
    public function testNamedCurve(ECPublicKeyAlgorithmIdentifier $ai)
    {
        $this->assertEquals(self::OID, $ai->namedCurve());
    }

    /**
     * @depends testDecode
     *
     * @param AlgorithmIdentifier $algo
     */
    public function testName(AlgorithmIdentifier $algo)
    {
        $this->assertIsString($algo->name());
    }
}
