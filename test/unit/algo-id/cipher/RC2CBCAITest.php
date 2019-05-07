<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\RC2CBCAlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 *
 * @internal
 */
class RC2CBCAITest extends TestCase
{
    const IV = '12345678';

    /**
     * @return Sequence
     */
    public function testEncode()
    {
        $ai = new RC2CBCAlgorithmIdentifier(64, self::IV);
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
        $this->assertInstanceOf(RC2CBCAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    public function testDecodeRFC2268OnlyIV()
    {
        $seq = new Sequence(
            new ObjectIdentifier(AlgorithmIdentifier::OID_RC2_CBC),
            new OctetString(self::IV));
        $ai = AlgorithmIdentifier::fromASN1($seq);
        $this->assertInstanceOf(RC2CBCAlgorithmIdentifier::class, $ai);
    }

    /**
     * @depends testDecode
     *
     * @param RC2CBCAlgorithmIdentifier $ai
     */
    public function testEffectiveKeyBits(RC2CBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(64, $ai->effectiveKeyBits());
    }

    /**
     * @depends testDecode
     *
     * @param RC2CBCAlgorithmIdentifier $ai
     */
    public function testIV(RC2CBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(self::IV, $ai->initializationVector());
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

    public function testEncodeNoIVFail()
    {
        $ai = new RC2CBCAlgorithmIdentifier();
        $this->expectException(\LogicException::class);
        $ai->toASN1();
    }

    /**
     * @depends testDecode
     *
     * @param RC2CBCAlgorithmIdentifier $ai
     */
    public function testBlockSize(RC2CBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(8, $ai->blockSize());
    }

    /**
     * @depends testDecode
     *
     * @param RC2CBCAlgorithmIdentifier $ai
     */
    public function testKeySize(RC2CBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(8, $ai->keySize());
    }

    public function testEncodeLargeKey()
    {
        $ai = new RC2CBCAlgorithmIdentifier(512, self::IV);
        $seq = $ai->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    /**
     * @depends testEncodeLargeKey
     *
     * @param Sequence $seq
     */
    public function testDecodeLargeKey(Sequence $seq)
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        $this->assertInstanceOf(RC2CBCAlgorithmIdentifier::class, $ai);
    }

    public function testInvalidIVSizeFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        new RC2CBCAlgorithmIdentifier(64, '1234');
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
