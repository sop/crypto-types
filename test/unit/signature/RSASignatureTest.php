<?php
use ASN1\Type\Primitive\BitString;
use Sop\CryptoTypes\Signature\RSASignature;

/**
 * @group signature
 */
class RSASignatureTest extends PHPUnit_Framework_TestCase
{
    /**
     *
     * @return \Sop\CryptoTypes\Signature\RSASignature
     */
    public function testFromSignatureString()
    {
        $sig = RSASignature::fromSignatureString("test");
        $this->assertInstanceOf(RSASignature::class, $sig);
        return $sig;
    }
    
    /**
     * @depends testFromSignatureString
     *
     * @param RSASignature $sig
     */
    public function testBitString(RSASignature $sig)
    {
        $this->assertInstanceOf(BitString::class, $sig->bitString());
    }
}
