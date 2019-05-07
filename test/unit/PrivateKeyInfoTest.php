<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\EC\ECPrivateKey;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPrivateKey;

/**
 * @group asn1
 * @group privatekey
 *
 * @internal
 */
class PrivateKeyInfoTest extends TestCase
{
    /**
     * @return PrivateKeyInfo
     */
    public function testDecodeRSA()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        $pki = PrivateKeyInfo::fromDER($pem->data());
        $this->assertInstanceOf(PrivateKeyInfo::class, $pki);
        return $pki;
    }

    /**
     * @depends testDecodeRSA
     *
     * @param PrivateKeyInfo $pki
     */
    public function testAlgoObj(PrivateKeyInfo $pki)
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
     * @param PrivateKeyInfo $pki
     */
    public function testGetRSAPrivateKey(PrivateKeyInfo $pki)
    {
        $pk = $pki->privateKey();
        $this->assertInstanceOf(RSAPrivateKey::class, $pk);
    }

    /**
     * @depends testDecodeRSA
     *
     * @param PrivateKeyInfo $pki
     */
    public function testPrivateKeyData(PrivateKeyInfo $pki)
    {
        $this->assertIsString($pki->privateKeyData());
    }

    /**
     * @return PrivateKeyInfo
     */
    public function testDecodeEC()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem');
        $pki = PrivateKeyInfo::fromDER($pem->data());
        $this->assertInstanceOf(PrivateKeyInfo::class, $pki);
        return $pki;
    }

    /**
     * @depends testDecodeEC
     *
     * @param PrivateKeyInfo $pki
     */
    public function testGetECPrivateKey(PrivateKeyInfo $pki)
    {
        $pk = $pki->privateKey();
        $this->assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends testGetECPrivateKey
     *
     * @param ECPrivateKey $pk
     */
    public function testECPrivateKeyHasNamedCurve(ECPrivateKey $pk)
    {
        $this->assertEquals(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1,
            $pk->namedCurve());
    }

    /**
     * @depends testDecodeRSA
     *
     * @param PrivateKeyInfo $pki
     */
    public function testGetRSAPublicKeyInfo(PrivateKeyInfo $pki)
    {
        $this->assertInstanceOf(PublicKeyInfo::class, $pki->publicKeyInfo());
    }

    /**
     * @depends testDecodeEC
     *
     * @param PrivateKeyInfo $pki
     */
    public function testGetECPublicKeyInfo(PrivateKeyInfo $pki)
    {
        $this->assertInstanceOf(PublicKeyInfo::class, $pki->publicKeyInfo());
    }

    /**
     * @return PrivateKeyInfo
     */
    public function testFromRSAPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        $this->assertInstanceOf(PrivateKeyInfo::class, $pki);
        return $pki;
    }

    /**
     * @depends testFromRSAPEM
     *
     * @param PrivateKeyInfo $pki
     */
    public function testToPEM(PrivateKeyInfo $pki)
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
        $ref = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        $this->assertEquals($ref, $pem);
    }

    public function testFromRSAPrivateKey()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        $this->assertInstanceOf(PrivateKeyInfo::class, $pki);
    }

    public function testFromECPrivateKey()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        $this->assertInstanceOf(PrivateKeyInfo::class, $pki);
    }

    /**
     * @depends testDecodeRSA
     *
     * @param PrivateKeyInfo $pki
     */
    public function testInvalidVersion(PrivateKeyInfo $pki)
    {
        $seq = $pki->toASN1();
        $seq = $seq->withReplaced(0, new Integer(2));
        $this->expectException(\UnexpectedValueException::class);
        PrivateKeyInfo::fromASN1($seq);
    }

    public function testInvalidPEMType()
    {
        $pem = new PEM('nope', '');
        $this->expectException(\UnexpectedValueException::class);
        PrivateKeyInfo::fromPEM($pem);
    }

    /**
     * @depends testDecodeRSA
     *
     * @param PrivateKeyInfo $pki
     */
    public function testInvalidAI(PrivateKeyInfo $pki)
    {
        $seq = $pki->toASN1();
        $ai = $seq->at(1)->asSequence()
            ->withReplaced(0, new ObjectIdentifier('1.3.6.1.3'));
        $seq = $seq->withReplaced(1, $ai);
        $this->expectException(\RuntimeException::class);
        PrivateKeyInfo::fromASN1($seq)->privateKey();
    }

    public function testInvalidECAlgoFail()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem');
        $seq = Sequence::fromDER($pem->data());
        $data = $seq->at(2)
            ->asOctetString()
            ->string();
        $pki = new PrivateKeyInfo(new PrivateKeyInfoTest_InvalidECAlgo(), $data);
        $this->expectException(\RuntimeException::class);
        $pki->privateKey();
    }
}

class PrivateKeyInfoTest_InvalidECAlgo extends SpecificAlgorithmIdentifier
{
    public function __construct()
    {
        $this->_oid = self::OID_EC_PUBLIC_KEY;
    }

    public function name(): string
    {
        return '';
    }

    protected function _paramsASN1(): ?Element
    {
        return null;
    }
}
