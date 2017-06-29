<?php
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\Integer;
use Sop\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA1AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Signature\ECSignature;
use Sop\CryptoTypes\Signature\GenericSignature;
use Sop\CryptoTypes\Signature\RSASignature;
use Sop\CryptoTypes\Signature\Signature;

/**
 * @group signature
 */
class SignatureTest extends PHPUnit_Framework_TestCase
{
    /**
     */
    public function testFromRSAAlgo()
    {
        $sig = Signature::fromSignatureData("test",
            new SHA1WithRSAEncryptionAlgorithmIdentifier());
        $this->assertInstanceOf(RSASignature::class, $sig);
    }
    
    /**
     */
    public function testFromECAlgo()
    {
        $seq = new Sequence(new Integer(1), new Integer(2));
        $sig = Signature::fromSignatureData($seq->toDER(),
            new ECDSAWithSHA1AlgorithmIdentifier());
        $this->assertInstanceOf(ECSignature::class, $sig);
    }
    
    /**
     */
    public function testFromUnknownAlgo()
    {
        $sig = Signature::fromSignatureData("",
            new GenericAlgorithmIdentifier("1.3.6.1.3"));
        $this->assertInstanceOf(GenericSignature::class, $sig);
    }
}
