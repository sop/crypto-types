<?php
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\Integer;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPrivateKey;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPublicKey;

/**
 * @group asn1
 * @group privatekey
 */
class RSAPrivateKeyTest extends PHPUnit_Framework_TestCase
{
    /**
     *
     * @return \Sop\CryptoTypes\Asymmetric\RSA\RSAPrivateKey
     */
    public function testDecode()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/rsa_private_key.pem");
        $pk = RSAPrivateKey::fromDER($pem->data());
        $this->assertInstanceOf(RSAPrivateKey::class, $pk);
        return $pk;
    }
    
    /**
     *
     * @return \Sop\CryptoTypes\Asymmetric\RSA\RSAPrivateKey
     */
    public function testFromPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/rsa_private_key.pem");
        $pk = RSAPrivateKey::fromPEM($pem);
        $this->assertInstanceOf(RSAPrivateKey::class, $pk);
        return $pk;
    }
    
    /**
     * @depends testFromPEM
     *
     * @param RSAPrivateKey $pk
     */
    public function testToPEM(RSAPrivateKey $pk)
    {
        $pem = $pk->toPEM();
        $this->assertInstanceOf(PEM::class, $pem);
        return $pem;
    }
    
    /**
     * @depends testToPEM
     *
     * @param PEM $pem
     */
    public function testRecodedPEM(PEM $pem)
    {
        $ref = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/rsa_private_key.pem");
        $this->assertEquals($ref, $pem);
    }
    
    /**
     */
    public function testFromPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem");
        $pk = RSAPrivateKey::fromPEM($pem);
        $this->assertInstanceOf(RSAPrivateKey::class, $pk);
    }
    
    /**
     * @depends testDecode
     *
     * @param RSAPrivateKey $pk
     */
    public function testGetPublicKey(RSAPrivateKey $pk)
    {
        $pub = $pk->publicKey();
        $ref = RSAPublicKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . "/rsa/rsa_public_key.pem"));
        $this->assertEquals($ref, $pub);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testInvalidVersion()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/rsa_private_key.pem");
        $seq = Sequence::fromDER($pem->data());
        $seq = $seq->withReplaced(0, new Integer(1));
        RSAPrivateKey::fromASN1($seq);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testInvalidPEMType()
    {
        $pem = new PEM("nope", "");
        RSAPrivateKey::fromPEM($pem);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testECKeyFail()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/ec/private_key.pem");
        RSAPrivateKey::fromPEM($pem);
    }
    
    /**
     * @depends testDecode
     *
     * @param RSAPrivateKey $pk
     */
    public function testModulus(RSAPrivateKey $pk)
    {
        $this->assertNotEmpty($pk->modulus());
    }
    
    /**
     * @depends testDecode
     *
     * @param RSAPrivateKey $pk
     */
    public function testPublicExponent(RSAPrivateKey $pk)
    {
        $this->assertNotEmpty($pk->publicExponent());
    }
    
    /**
     * @depends testDecode
     *
     * @param RSAPrivateKey $pk
     */
    public function testPrivateExponent(RSAPrivateKey $pk)
    {
        $this->assertNotEmpty($pk->privateExponent());
    }
    
    /**
     * @depends testDecode
     *
     * @param RSAPrivateKey $pk
     */
    public function testPrime1(RSAPrivateKey $pk)
    {
        $this->assertNotEmpty($pk->prime1());
    }
    
    /**
     * @depends testDecode
     *
     * @param RSAPrivateKey $pk
     */
    public function testPrime2(RSAPrivateKey $pk)
    {
        $this->assertNotEmpty($pk->prime2());
    }
    
    /**
     * @depends testDecode
     *
     * @param RSAPrivateKey $pk
     */
    public function testExponent1(RSAPrivateKey $pk)
    {
        $this->assertNotEmpty($pk->exponent1());
    }
    
    /**
     * @depends testDecode
     *
     * @param RSAPrivateKey $pk
     */
    public function testExponent2(RSAPrivateKey $pk)
    {
        $this->assertNotEmpty($pk->exponent2());
    }
    
    /**
     * @depends testDecode
     *
     * @param RSAPrivateKey $pk
     */
    public function testCoefficient(RSAPrivateKey $pk)
    {
        $this->assertNotEmpty($pk->coefficient());
    }
    
    /**
     * @depends testDecode
     *
     * @param RSAPrivateKey $pk
     */
    public function testPrivateKeyInfo(RSAPrivateKey $pk)
    {
        $pki = $pk->privateKeyInfo();
        $this->assertInstanceOf(PrivateKeyInfo::class, $pki);
    }
}
