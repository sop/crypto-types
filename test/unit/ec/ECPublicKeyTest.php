<?php
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\EC\ECPublicKey;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;

/**
 * @group asn1
 * @group ec
 */
class ECPublicKeyTest extends PHPUnit_Framework_TestCase
{
    /**
     *
     * @return \Sop\CryptoTypes\Asymmetric\EC\ECPublicKey
     */
    public function testFromPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/ec/public_key.pem");
        $pk = ECPublicKey::fromPEM($pem);
        $this->assertInstanceOf(ECPublicKey::class, $pk);
        return $pk;
    }
    
    /**
     * @depends testFromPEM
     *
     * @param ECPublicKey $pk
     */
    public function testECPoint(ECPublicKey $pk)
    {
        $this->assertNotEmpty($pk->ECPoint());
    }
    
    /**
     * @depends testFromPEM
     *
     * @param ECPublicKey $pk
     */
    public function testPublicKeyInfo(ECPublicKey $pk)
    {
        $pki = $pk->publicKeyInfo();
        $this->assertInstanceOf(PublicKeyInfo::class, $pki);
    }
    
    /**
     * @expectedException LogicException
     */
    public function testNoNamedCurve()
    {
        $pk = new ECPublicKey("\x04\0\0");
        $pk->publicKeyInfo();
    }
    
    /**
     * @expectedException InvalidArgumentException
     */
    public function testInvalidECPoint()
    {
        new ECPublicKey("\x0");
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testInvalidPEMType()
    {
        $pem = new PEM("nope", "");
        ECPublicKey::fromPEM($pem);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testRSAKeyFail()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/public_key.pem");
        ECPublicKey::fromPEM($pem);
    }
    
    /**
     * @depends testFromPEM
     *
     * @param ECPublicKey $pk
     */
    public function testToDER(ECPublicKey $pk)
    {
        $this->assertNotEmpty($pk->toDER());
    }
    
    /**
     * @depends testFromPEM
     *
     * @param ECPublicKey $pk
     */
    public function testCurvePoint(ECPublicKey $pk)
    {
        $point = $pk->curvePoint();
        $this->assertContainsOnly("string", $point);
        return $point;
    }
    
    /**
     * @depends testFromPEM
     *
     * @param ECPublicKey $pk
     */
    public function testHasNamedCurve(ECPublicKey $pk)
    {
        $this->assertTrue($pk->hasNamedCurve());
    }
    
    /**
     * @depends testFromPEM
     *
     * @param ECPublicKey $pk
     */
    public function testNamedCurve(ECPublicKey $pk)
    {
        $this->assertEquals(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1,
            $pk->namedCurve());
    }
    
    /**
     * @expectedException LogicException
     */
    public function testNoCurveFail()
    {
        $pk = new ECPublicKey("\x4\0\0");
        $pk->namedCurve();
    }
    
    /**
     * @expectedException RuntimeException
     */
    public function testCompressedFail()
    {
        $pk = new ECPublicKey("\x3\0");
        $pk->curvePoint();
    }
    
    /**
     * @depends testCurvePoint
     */
    public function testFromCoordinates(array $points)
    {
        list($x, $y) = $points;
        $pk = ECPublicKey::fromCoordinates($x, $y,
            ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1);
        $this->assertInstanceOf(ECPublicKey::class, $pk);
        return $pk;
    }
    
    /**
     * @depends testFromPEM
     * @depends testFromCoordinates
     *
     * @param ECPublicKey $ref
     * @param ECPublicKey $new
     */
    public function testFromCoordsEqualsPEM(ECPublicKey $ref, ECPublicKey $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     */
    public function testFromCoordsUnknownCurve()
    {
        $pk = ECPublicKey::fromCoordinates(0, 0, "1.3.6.1.3");
        $this->assertInstanceOf(ECPublicKey::class, $pk);
    }
}
