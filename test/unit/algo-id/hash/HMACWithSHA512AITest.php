<?php
declare(strict_types=1);

use ASN1\Type\Constructed\Sequence;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Hash\HMACWithSHA512AlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 */
class HMACWithSHA512AITest extends PHPUnit_Framework_TestCase
{
    /**
     *
     * @return \ASN1\Type\Constructed\Sequence
     */
    public function testEncode()
    {
        $ai = new HMACWithSHA512AlgorithmIdentifier();
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
        $this->assertInstanceOf(HMACWithSHA512AlgorithmIdentifier::class, $ai);
        return $ai;
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
