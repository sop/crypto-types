<?php
use ASN1\Type\Constructed\Sequence;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\AES192CBCAlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 */
class AES192CBCAITest extends PHPUnit_Framework_TestCase
{
    const IV = "0123456789abcdef";
    
    /**
     *
     * @return \ASN1\Type\Constructed\Sequence
     */
    public function testEncode()
    {
        $ai = new AES192CBCAlgorithmIdentifier(self::IV);
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
        $this->assertInstanceOf(AES192CBCAlgorithmIdentifier::class, $ai);
        return $ai;
    }
    
    /**
     * @depends testDecode
     *
     * @param AES192CBCAlgorithmIdentifier $ai
     */
    public function testIV(AES192CBCAlgorithmIdentifier $ai)
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
        $ai = new AES192CBCAlgorithmIdentifier();
        $ai->toASN1();
    }
    
    /**
     * @depends testDecode
     *
     * @param AES192CBCAlgorithmIdentifier $ai
     */
    public function testBlockSize(AES192CBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(16, $ai->blockSize());
    }
    
    /**
     * @depends testDecode
     *
     * @param AES192CBCAlgorithmIdentifier $ai
     */
    public function testKeySize(AES192CBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(24, $ai->keySize());
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testInvalidIVSizeFail()
    {
        new AES192CBCAlgorithmIdentifier("1234");
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
