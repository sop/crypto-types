<?php
declare(strict_types=1);

use ASN1\Type\Constructed\Sequence;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\AES128CBCAlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 */
class AES128CBCAITest extends PHPUnit_Framework_TestCase
{
    const IV = "0123456789abcdef";
    
    /**
     *
     * @return \ASN1\Type\Constructed\Sequence
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
     * @expectedException UnexpectedValueException
     *
     * @param Sequence $seq
     */
    public function testDecodeNoParamsFail(Sequence $seq)
    {
        $seq = $seq->withoutElement(1);
        AlgorithmIdentifier::fromASN1($seq);
    }
    
    /**
     * @expectedException LogicException
     */
    public function testEncodeNoIVFail()
    {
        $ai = new AES128CBCAlgorithmIdentifier();
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
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testInvalidIVSizeFail()
    {
        new AES128CBCAlgorithmIdentifier("1234");
    }
    
    /**
     * @depends testDecode
     *
     * @param AlgorithmIdentifier $algo
     */
    public function testName(AlgorithmIdentifier $algo)
    {
        $this->assertInternalType("string", $algo->name());
    }
}
