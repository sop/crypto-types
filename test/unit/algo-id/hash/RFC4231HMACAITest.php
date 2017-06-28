<?php
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\Boolean;
use ASN1\Type\Primitive\NullType;
use ASN1\Type\Primitive\ObjectIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Hash\HMACWithSHA256AlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 */
class RFC4231HMACAITest extends PHPUnit_Framework_TestCase
{
    /**
     */
    public function testDecodeWithParams()
    {
        $seq = new Sequence(
            new ObjectIdentifier(AlgorithmIdentifier::OID_HMAC_WITH_SHA256), 
            new NullType());
        $ai = AlgorithmIdentifier::fromASN1($seq);
        $this->assertInstanceOf(HMACWithSHA256AlgorithmIdentifier::class, $ai);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testDecodeWithInvalidParamsFail()
    {
        $seq = new Sequence(
            new ObjectIdentifier(AlgorithmIdentifier::OID_HMAC_WITH_SHA256), 
            new Boolean(true));
        AlgorithmIdentifier::fromASN1($seq);
    }
}
