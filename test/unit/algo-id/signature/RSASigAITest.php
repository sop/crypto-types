<?php
declare(strict_types=1);

use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 */
class RSASigAITest extends PHPUnit_Framework_TestCase
{
    /**
     */
    public function testSupportsKeyAlgorithm()
    {
        $sig_algo = new SHA1WithRSAEncryptionAlgorithmIdentifier();
        $key_algo = new RSAEncryptionAlgorithmIdentifier();
        $this->assertTrue($sig_algo->supportsKeyAlgorithm($key_algo));
    }
    
    /**
     */
    public function testDoesntSupportsKeyAlgorithm()
    {
        $sig_algo = new SHA1WithRSAEncryptionAlgorithmIdentifier();
        $key_algo = new ECPublicKeyAlgorithmIdentifier(
            ECPublicKeyAlgorithmIdentifier::CURVE_PRIME192V1);
        $this->assertFalse($sig_algo->supportsKeyAlgorithm($key_algo));
    }
}


