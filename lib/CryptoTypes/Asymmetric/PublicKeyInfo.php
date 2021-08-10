<?php

declare(strict_types = 1);

namespace Sop\CryptoTypes\Asymmetric;

use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;

/**
 * Implements X.509 SubjectPublicKeyInfo ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.1
 */
class PublicKeyInfo
{
    /**
     * Algorithm identifier.
     *
     * @var AlgorithmIdentifierType
     */
    protected $_algo;

    /**
     * Public key.
     *
     * @var BitString
     */
    protected $_publicKey;

    /**
     * Constructor.
     *
     * @param AlgorithmIdentifierType $algo Algorithm
     * @param string                  $key  Public key data
     */
    public function __construct(AlgorithmIdentifierType $algo, string $key)
    {
        $this->_algo = $algo;
        $this->_publicKey = new BitString($key);
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(Sequence $seq): self
    {
        $algo = AlgorithmIdentifier::fromASN1($seq->at(0)->asSequence());
        $key = $seq->at(1)->asBitString();
        return new self($algo, $key->string());
    }

    /**
     * Initialize from public key data as a bit string.
     */
    public static function fromBitString(
        AlgorithmIdentifierType $algo, BitString $key): self
    {
        $obj = new self($algo, '');
        $obj->_publicKey = $key;
        return $obj;
    }

    /**
     * Inititalize from a PublicKey.
     */
    public static function fromPublicKey(PublicKey $public_key): self
    {
        return new self($public_key->algorithmIdentifier(),
            $public_key->subjectPublicKeyData());
    }

    /**
     * Initialize from PEM.
     *
     * @throws \UnexpectedValueException
     */
    public static function fromPEM(PEM $pem): self
    {
        switch ($pem->type()) {
            case PEM::TYPE_PUBLIC_KEY:
                return self::fromDER($pem->data());
            case PEM::TYPE_RSA_PUBLIC_KEY:
                return RSA\RSAPublicKey::fromDER($pem->data())->publicKeyInfo();
        }
        throw new \UnexpectedValueException('Invalid PEM type.');
    }

    /**
     * Initialize from DER data.
     */
    public static function fromDER(string $data): self
    {
        return self::fromASN1(UnspecifiedType::fromDER($data)->asSequence());
    }

    /**
     * Get algorithm identifier.
     */
    public function algorithmIdentifier(): AlgorithmIdentifierType
    {
        return $this->_algo;
    }

    /**
     * Get public key data.
     */
    public function publicKeyData(): string
    {
        return $this->_publicKey->string();
    }

    /**
     * Get public key.
     *
     * @throws \RuntimeException
     */
    public function publicKey(): PublicKey
    {
        $algo = $this->algorithmIdentifier();
        switch ($algo->oid()) {
            // RSA
            case AlgorithmIdentifier::OID_RSA_ENCRYPTION:
                return RSA\RSAPublicKey::fromDER($this->publicKeyData());
            // Elliptic Curve
            case AlgorithmIdentifier::OID_EC_PUBLIC_KEY:
                if (!$algo instanceof ECPublicKeyAlgorithmIdentifier) {
                    throw new \UnexpectedValueException('Not an EC algorithm.');
                }
                // ECPoint is directly mapped into public key data
                return new EC\ECPublicKey($this->publicKeyData(),
                    $algo->namedCurve());
            // Ed25519
            case AlgorithmIdentifier::OID_ED25519:
                return new RFC8410\Curve25519\Ed25519PublicKey(
                    $this->publicKeyData());
            // X25519
            case AlgorithmIdentifier::OID_X25519:
                return new RFC8410\Curve25519\X25519PublicKey(
                    $this->publicKeyData());
            // Ed448
            case AlgorithmIdentifier::OID_ED448:
                return new RFC8410\Curve448\Ed448PublicKey(
                    $this->publicKeyData());
            // X448
            case AlgorithmIdentifier::OID_X448:
                return new RFC8410\Curve448\X448PublicKey(
                    $this->publicKeyData());
        }
        throw new \RuntimeException(
            'Public key ' . $algo->name() . ' not supported.');
    }

    /**
     * Get key identifier using method 1 as described by RFC 5280.
     *
     * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.2
     *
     * @return string 20 bytes (160 bits) long identifier
     */
    public function keyIdentifier(): string
    {
        return sha1($this->publicKeyData(), true);
    }

    /**
     * Get key identifier using method 2 as described by RFC 5280.
     *
     * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.2
     *
     * @return string 8 bytes (64 bits) long identifier
     */
    public function keyIdentifier64(): string
    {
        $id = substr($this->keyIdentifier(), -8);
        $c = (ord($id[0]) & 0x0f) | 0x40;
        $id[0] = chr($c);
        return $id;
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        return new Sequence($this->_algo->toASN1(), $this->_publicKey);
    }

    /**
     * Generate DER encoding.
     */
    public function toDER(): string
    {
        return $this->toASN1()->toDER();
    }

    /**
     * Generate PEM.
     */
    public function toPEM(): PEM
    {
        return new PEM(PEM::TYPE_PUBLIC_KEY, $this->toDER());
    }
}
