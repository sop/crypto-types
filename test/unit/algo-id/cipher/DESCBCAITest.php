<?php
declare(strict_types=1);

use ASN1\Type\Constructed\Sequence;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\DESCBCAlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 */
class DESCBCAITest extends PHPUnit_Framework_TestCase
{
    const IV = "12345678";
    
    /**
     *
     * @return \ASN1\Type\Constructed\Sequence
     */
    public function testEncode()
    {
        $ai = new DESCBCAlgorithmIdentifier(self::IV);
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
        $this->assertInstanceOf(DESCBCAlgorithmIdentifier::class, $ai);
        return $ai;
    }
    
    /**
     * @depends testDecode
     *
     * @param DESCBCAlgorithmIdentifier $ai
     */
    public function testIV(DESCBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(self::IV, $ai->initializationVector());
    }
    
    /**
     * @depends testDecode
     *
     * @param DESCBCAlgorithmIdentifier $ai
     */
    public function testWithIV(DESCBCAlgorithmIdentifier $ai)
    {
        $ai2 = $ai->withInitializationVector("testtest");
        $this->assertNotEquals($ai2, $ai);
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
        $ai = new DESCBCAlgorithmIdentifier();
        $ai->toASN1();
    }
    
    /**
     * @depends testDecode
     *
     * @param DESCBCAlgorithmIdentifier $ai
     */
    public function testBlockSize(DESCBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(8, $ai->blockSize());
    }
    
    /**
     * @depends testDecode
     *
     * @param DESCBCAlgorithmIdentifier $ai
     */
    public function testKeySize(DESCBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(8, $ai->keySize());
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testInvalidIVSizeFail()
    {
        new DESCBCAlgorithmIdentifier("1234");
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
