<?php
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA1AlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 */
class ECDSAAITest extends PHPUnit_Framework_TestCase
{
    /**
     */
    public function testSupportsKeyAlgorithm()
    {
        $sig_algo = new ECDSAWithSHA1AlgorithmIdentifier();
        $key_algo = new ECPublicKeyAlgorithmIdentifier(
            ECPublicKeyAlgorithmIdentifier::CURVE_PRIME192V1);
        $this->assertTrue($sig_algo->supportsKeyAlgorithm($key_algo));
    }
    
    /**
     */
    public function testDoesntSupportsKeyAlgorithm()
    {
        $sig_algo = new ECDSAWithSHA1AlgorithmIdentifier();
        $key_algo = new RSAEncryptionAlgorithmIdentifier();
        $this->assertFalse($sig_algo->supportsKeyAlgorithm($key_algo));
    }
}


