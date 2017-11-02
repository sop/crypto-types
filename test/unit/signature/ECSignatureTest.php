<?php
declare(strict_types=1);

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\BitString;
use Sop\CryptoTypes\Signature\ECSignature;

/**
 * @group signature
 */
class ECSignatureTest extends PHPUnit_Framework_TestCase
{
    /**
     *
     * @return \Sop\CryptoTypes\Signature\ECSignature
     */
    public function testCreate()
    {
        $sig = new ECSignature("123456789", "987654321");
        $this->assertInstanceOf(ECSignature::class, $sig);
        return $sig;
    }
    
    /**
     * @depends testCreate
     *
     * @param ECSignature $sig
     */
    public function testEncode(ECSignature $sig)
    {
        $el = $sig->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
    }
    
    /**
     * @depends testCreate
     *
     * @param ECSignature $sig
     */
    public function testToDER(ECSignature $sig)
    {
        $der = $sig->toDER();
        $this->assertInternalType("string", $der);
        return $der;
    }
    
    /**
     * @depends testToDER
     *
     * @param string $data
     */
    public function testDecode($data)
    {
        $sig = ECSignature::fromDER($data);
        $this->assertInstanceOf(ECSignature::class, $sig);
        return $sig;
    }
    
    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param ECSignature $ref
     * @param ECSignature $sig
     */
    public function testRecoded(ECSignature $ref, ECSignature $sig)
    {
        $this->assertEquals($ref, $sig);
    }
    
    /**
     * @depends testCreate
     *
     * @param ECSignature $sig
     */
    public function testRValue(ECSignature $sig)
    {
        $this->assertEquals("123456789", $sig->r());
    }
    
    /**
     * @depends testCreate
     *
     * @param ECSignature $sig
     */
    public function testSValue(ECSignature $sig)
    {
        $this->assertEquals("987654321", $sig->s());
    }
    
    /**
     * @depends testCreate
     *
     * @param ECSignature $sig
     */
    public function testBitString(ECSignature $sig)
    {
        $this->assertInstanceOf(BitString::class, $sig->bitString());
    }
}
