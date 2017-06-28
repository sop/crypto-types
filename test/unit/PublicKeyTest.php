<?php
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\EC\ECPublicKey;
use Sop\CryptoTypes\Asymmetric\PublicKey;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPublicKey;

/**
 * @group asn1
 * @group publickey
 */
class PublicKeyTest extends PHPUnit_Framework_TestCase
{
    /**
     */
    public function testFromRSAPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/rsa_public_key.pem");
        $pk = PublicKey::fromPEM($pem);
        $this->assertInstanceOf(RSAPublicKey::class, $pk);
    }
    
    /**
     */
    public function testFromRSAPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/public_key.pem");
        $pk = PublicKey::fromPEM($pem);
        $this->assertInstanceOf(RSAPublicKey::class, $pk);
    }
    
    /**
     *
     * @return \Sop\CryptoTypes\Asymmetric\PublicKey
     */
    public function testFromECPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/ec/public_key.pem");
        $pk = PublicKey::fromPEM($pem);
        $this->assertInstanceOf(ECPublicKey::class, $pk);
        return $pk;
    }
    
    /**
     */
    public function testRSAPKIRecode()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/public_key.pem");
        $result = PublicKey::fromPEM($pem)->publicKeyInfo()->toPEM();
        $this->assertEquals($pem, $result);
    }
    
    /**
     */
    public function testECPKIRecode()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/ec/public_key.pem");
        $result = PublicKey::fromPEM($pem)->publicKeyInfo()->toPEM();
        $this->assertEquals($pem, $result);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testInvalidPEM()
    {
        $pem = new PEM("nope", "");
        PublicKey::fromPEM($pem);
    }
}
