<?php
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\EC\ECPrivateKey;
use Sop\CryptoTypes\Asymmetric\PrivateKey;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPrivateKey;

/**
 * @group asn1
 * @group privatekey
 */
class PrivateKeyTest extends PHPUnit_Framework_TestCase
{
    /**
     */
    public function testFromRSAPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/rsa_private_key.pem");
        $pk = PrivateKey::fromPEM($pem);
        $this->assertInstanceOf(RSAPrivateKey::class, $pk);
    }
    
    /**
     */
    public function testFromRSAPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem");
        $pk = PrivateKey::fromPEM($pem);
        $this->assertInstanceOf(RSAPrivateKey::class, $pk);
    }
    
    /**
     *
     * @return \Sop\CryptoTypes\Asymmetric\PrivateKey
     */
    public function testFromECPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/ec/ec_private_key.pem");
        $pk = PrivateKey::fromPEM($pem);
        $this->assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }
    
    /**
     * @depends testFromECPEM
     *
     * @param ECPrivateKey $pk
     */
    public function testECPEMHasNamedCurve(ECPrivateKey $pk)
    {
        $this->assertEquals(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1, 
            $pk->namedCurve());
    }
    
    /**
     *
     * @return \Sop\CryptoTypes\Asymmetric\PrivateKey
     */
    public function testFromECPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/ec/private_key.pem");
        $pk = PrivateKey::fromPEM($pem);
        $this->assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }
    
    /**
     * @depends testFromECPKIPEM
     *
     * @param ECPrivateKey $pk
     */
    public function testECPKIPEMHasNamedCurve(ECPrivateKey $pk)
    {
        $this->assertEquals(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1, 
            $pk->namedCurve());
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testInvalidPEMType()
    {
        $pem = new PEM("nope", "");
        PrivateKey::fromPEM($pem);
    }
}
