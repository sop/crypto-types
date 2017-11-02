<?php
declare(strict_types=1);

use ASN1\Type\Constructed\Sequence;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 */
class ECPKAITest extends PHPUnit_Framework_TestCase
{
    const OID = "1.2.840.10045.3.1.7";
    
    /**
     *
     * @return \ASN1\Type\Constructed\Sequence
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
        $this->assertInternalType("string", $algo->name());
    }
}
