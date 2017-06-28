<?php
use ASN1\Type\Primitive\ObjectIdentifier;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\EC\ECPublicKey;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPublicKey;

/**
 * @group asn1
 * @group publickey
 */
class PublicKeyInfoTest extends PHPUnit_Framework_TestCase
{
    /**
     *
     * @return \Sop\CryptoTypes\Asymmetric\PublicKeyInfo
     */
    public function testDecodeRSA()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/public_key.pem");
        $pki = PublicKeyInfo::fromDER($pem->data());
        $this->assertInstanceOf(PublicKeyInfo::class, $pki);
        return $pki;
    }
    
    /**
     * @depends testDecodeRSA
     *
     * @param PublicKeyInfo $pki
     */
    public function testAlgoObj(PublicKeyInfo $pki)
    {
        $ref = new RSAEncryptionAlgorithmIdentifier();
        $algo = $pki->algorithmIdentifier();
        $this->assertEquals($ref, $algo);
        return $algo;
    }
    
    /**
     * @depends testAlgoObj
     *
     * @param AlgorithmIdentifier $algo
     */
    public function testAlgoOID(AlgorithmIdentifier $algo)
    {
        $this->assertEquals(AlgorithmIdentifier::OID_RSA_ENCRYPTION, 
            $algo->oid());
    }
    
    /**
     * @depends testDecodeRSA
     *
     * @param PublicKeyInfo $pki
     */
    public function testGetRSAPublicKey(PublicKeyInfo $pki)
    {
        $pk = $pki->publicKey();
        $this->assertInstanceOf(RSAPublicKey::class, $pk);
    }
    
    /**
     *
     * @return \Sop\CryptoTypes\Asymmetric\PublicKeyInfo
     */
    public function testDecodeEC()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/ec/public_key.pem");
        $pki = PublicKeyInfo::fromDER($pem->data());
        $this->assertInstanceOf(PublicKeyInfo::class, $pki);
        return $pki;
    }
    
    /**
     * @depends testDecodeEC
     *
     * @param PublicKeyInfo $pki
     */
    public function testGetECPublicKey(PublicKeyInfo $pki)
    {
        $pk = $pki->publicKey();
        $this->assertInstanceOf(ECPublicKey::class, $pk);
    }
    
    /**
     *
     * @return \Sop\CryptoTypes\Asymmetric\PublicKeyInfo
     */
    public function testFromRSAPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/public_key.pem");
        $pki = PublicKeyInfo::fromPEM($pem);
        $this->assertInstanceOf(PublicKeyInfo::class, $pki);
        return $pki;
    }
    
    /**
     * @depends testFromRSAPEM
     *
     * @param PublicKeyInfo $pki
     */
    public function testToPEM(PublicKeyInfo $pki)
    {
        $pem = $pki->toPEM();
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
        $ref = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/public_key.pem");
        $this->assertEquals($ref, $pem);
    }
    
    /**
     */
    public function testDecodeFromRSAPublicKey()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/rsa_public_key.pem");
        $pki = PublicKeyInfo::fromPEM($pem);
        $this->assertInstanceOf(PublicKeyInfo::class, $pki);
    }
    
    /**
     * @depends testDecodeRSA
     *
     * @param PublicKeyInfo $pki
     */
    public function testKeyIdentifier(PublicKeyInfo $pki)
    {
        $id = $pki->keyIdentifier();
        $this->assertEquals(160, strlen($id) * 8);
    }
    
    /**
     * @depends testDecodeRSA
     *
     * @param PublicKeyInfo $pki
     */
    public function testKeyIdentifier64(PublicKeyInfo $pki)
    {
        $id = $pki->keyIdentifier64();
        $this->assertEquals(64, strlen($id) * 8);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testInvalidPEMType()
    {
        $pem = new PEM("nope", "");
        PublicKeyInfo::fromPEM($pem);
    }
    
    /**
     * @depends testDecodeRSA
     * @expectedException RuntimeException
     *
     * @param PublicKeyInfo $pki
     */
    public function testInvalidAI(PublicKeyInfo $pki)
    {
        $seq = $pki->toASN1();
        $ai = $seq->at(0)->withReplaced(0, new ObjectIdentifier("1.3.6.1.3"));
        $seq = $seq->withReplaced(0, $ai);
        PublicKeyInfo::fromASN1($seq)->publicKey();
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testInvalidECAlgoFail()
    {
        $pki = new PublicKeyInfo(new PubliceKeyInfoTest_InvalidECAlgo(), "");
        $pki->publicKey();
    }
}

class PubliceKeyInfoTest_InvalidECAlgo extends SpecificAlgorithmIdentifier
{
    public function __construct()
    {
        $this->_oid = self::OID_EC_PUBLIC_KEY;
    }
    public function name()
    {
        return "";
    }
    protected function _paramsASN1()
    {
        return null;
    }
}
