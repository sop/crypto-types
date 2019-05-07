<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\AES128CBCAlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 *
 * @internal
 */
class AES128CBCAITest extends TestCase
{
    const IV = '0123456789abcdef';

    /**
     * @return Sequence
     */
    public function testEncode()
    {
        $ai = new AES128CBCAlgorithmIdentifier(self::IV);
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
        $this->assertInstanceOf(AES128CBCAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends testDecode
     *
     * @param AES128CBCAlgorithmIdentifier $ai
     */
    public function testIV(AES128CBCAlgorithmIdentifier $ai)
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
        $ai = new AES128CBCAlgorithmIdentifier();
        $this->expectException(\LogicException::class);
        $ai->toASN1();
    }

    /**
     * @depends testDecode
     *
     * @param AES128CBCAlgorithmIdentifier $ai
     */
    public function testBlockSize(AES128CBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(16, $ai->blockSize());
    }

    /**
     * @depends testDecode
     *
     * @param AES128CBCAlgorithmIdentifier $ai
     */
    public function testKeySize(AES128CBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(16, $ai->keySize());
    }

    public function testInvalidIVSizeFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        new AES128CBCAlgorithmIdentifier('1234');
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
