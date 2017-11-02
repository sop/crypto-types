<?php
declare(strict_types=1);

use ASN1\Type\Primitive\BitString;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Signature\GenericSignature;

/**
 * @group signature
 */
class GenericSignatureTest extends PHPUnit_Framework_TestCase
{
    /**
     *
     * @return \Sop\CryptoTypes\Signature\GenericSignature
     */
    public function testCreate()
    {
        $sig = new GenericSignature(new BitString("test"),
            new SHA1WithRSAEncryptionAlgorithmIdentifier());
        $this->assertInstanceOf(GenericSignature::class, $sig);
        return $sig;
    }
    
    /**
     * @depends testCreate
     *
     * @param GenericSignature $sig
     */
    public function testBitString(GenericSignature $sig)
    {
        $this->assertInstanceOf(BitString::class, $sig->bitString());
    }
    
    /**
     * @depends testCreate
     *
     * @param GenericSignature $sig
     */
    public function testSignatureAlgorithm(GenericSignature $sig)
    {
        $this->assertInstanceOf(AlgorithmIdentifier::class,
            $sig->signatureAlgorithm());
    }
}
