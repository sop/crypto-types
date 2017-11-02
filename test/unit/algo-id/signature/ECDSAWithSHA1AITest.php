<?php
declare(strict_types=1);

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\NullType;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA1AlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 */
class ECDSAWithSHA1AITest extends PHPUnit_Framework_TestCase
{
    /**
     *
     * @return \ASN1\Type\Constructed\Sequence
     */
    public function testEncode()
    {
        $ai = new ECDSAWithSHA1AlgorithmIdentifier();
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
        $this->assertInstanceOf(ECDSAWithSHA1AlgorithmIdentifier::class, $ai);
        return $ai;
    }
    
    /**
     * @depends testEncode
     * @expectedException UnexpectedValueException
     *
     * @param Sequence $seq
     */
    public function testDecodeWithParamsFail(Sequence $seq)
    {
        $seq = $seq->withInserted(1, new NullType());
        AlgorithmIdentifier::fromASN1($seq);
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
