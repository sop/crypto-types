<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\EC\ECPrivateKey;
use Sop\CryptoTypes\Asymmetric\EC\ECPublicKey;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;

/**
 * @group asn1
 * @group ec
 *
 * @internal
 */
class ECPrivateKeyTest extends TestCase
{
    /**
     * @return ECPrivateKey
     */
    public function testDecode()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        $pk = ECPrivateKey::fromDER($pem->data());
        $this->assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @return ECPrivateKey
     */
    public function testFromPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        $pk = ECPrivateKey::fromPEM($pem);
        $this->assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends testFromPEM
     */
    public function testToPEM(ECPrivateKey $pk)
    {
        $pem = $pk->toPEM();
        $this->assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    /**
     * @depends testToPEM
     */
    public function testRecodedPEM(PEM $pem)
    {
        $ref = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        $this->assertEquals($ref, $pem);
    }

    /**
     * @return ECPrivateKey
     */
    public function testFromPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem');
        $pk = ECPrivateKey::fromPEM($pem);
        $this->assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends testDecode
     */
    public function testPrivateKeyOctets(ECPrivateKey $pk)
    {
        $octets = $pk->privateKeyOctets();
        $this->assertIsString($octets);
    }

    /**
     * @depends testFromPKIPEM
     */
    public function testHasNamedCurveFromPKI(ECPrivateKey $pk)
    {
        $this->assertEquals(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1,
            $pk->namedCurve());
    }

    /**
     * @depends testDecode
     */
    public function testGetPublicKey(ECPrivateKey $pk)
    {
        $pub = $pk->publicKey();
        $ref = ECPublicKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/ec/public_key.pem'));
        $this->assertEquals($ref, $pub);
    }

    /**
     * @depends testDecode
     */
    public function testGetPrivateKeyInfo(ECPrivateKey $pk)
    {
        $pki = $pk->privateKeyInfo();
        $this->assertInstanceOf(PrivateKeyInfo::class, $pki);
    }

    public function testInvalidVersion()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        $seq = Sequence::fromDER($pem->data());
        $seq = $seq->withReplaced(0, new Integer(0));
        $this->expectException(\UnexpectedValueException::class);
        ECPrivateKey::fromASN1($seq);
    }

    public function testInvalidPEMType()
    {
        $pem = new PEM('nope', '');
        $this->expectException(\UnexpectedValueException::class);
        ECPrivateKey::fromPEM($pem);
    }

    public function testRSAKeyFail()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        $this->expectException(\UnexpectedValueException::class);
        ECPrivateKey::fromPEM($pem);
    }

    /**
     * @depends testDecode
     */
    public function testNamedCurveNotSet(ECPrivateKey $pk)
    {
        $pk = $pk->withNamedCurve(null);
        $this->expectException(\LogicException::class);
        $pk->namedCurve();
    }

    public function testPublicKeyNotSet()
    {
        $pk = new ECPrivateKey("\0");
        $this->expectException(\LogicException::class);
        $pk->publicKey();
    }
}
