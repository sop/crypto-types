<?php

declare(strict_types = 1);

namespace Sop\CryptoTypes\Asymmetric\RSA;

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\Integer;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PublicKey;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;

/**
 * Implements PKCS #1 RSAPublicKey ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc2437#section-11.1.1
 */
class RSAPublicKey extends PublicKey
{
    /**
     * Modulus.
     *
     * @var int|string $_modulus
     */
    protected $_modulus;
    
    /**
     * Public exponent.
     *
     * @var int|string $_publicExponent
     */
    protected $_publicExponent;
    
    /**
     * Constructor.
     *
     * @param int|string $n Modulus
     * @param int|string $e Public exponent
     */
    public function __construct($n, $e)
    {
        $this->_modulus = $n;
        $this->_publicExponent = $e;
    }
    
    /**
     * Initialize from ASN.1.
     *
     * @param Sequence $seq
     * @return self
     */
    public static function fromASN1(Sequence $seq): self
    {
        $n = $seq->at(0)
            ->asInteger()
            ->number();
        $e = $seq->at(1)
            ->asInteger()
            ->number();
        return new self($n, $e);
    }
    
    /**
     * Initialize from DER data.
     *
     * @param string $data
     * @return self
     */
    public static function fromDER(string $data): self
    {
        return self::fromASN1(Sequence::fromDER($data));
    }
    
    /**
     *
     * @see PublicKey::fromPEM()
     * @param PEM $pem
     * @throws \UnexpectedValueException
     * @return self
     */
    public static function fromPEM(PEM $pem): self
    {
        switch ($pem->type()) {
            case PEM::TYPE_RSA_PUBLIC_KEY:
                return self::fromDER($pem->data());
            case PEM::TYPE_PUBLIC_KEY:
                $pki = PublicKeyInfo::fromDER($pem->data());
                if (AlgorithmIdentifier::OID_RSA_ENCRYPTION !=
                     $pki->algorithmIdentifier()->oid()) {
                    throw new \UnexpectedValueException("Not an RSA public key.");
                }
                return self::fromDER($pki->publicKeyData());
        }
        throw new \UnexpectedValueException("Invalid PEM type " . $pem->type());
    }
    
    /**
     * Get modulus.
     *
     * @return int|string
     */
    public function modulus()
    {
        return $this->_modulus;
    }
    
    /**
     * Get public exponent.
     *
     * @return int|string
     */
    public function publicExponent()
    {
        return $this->_publicExponent;
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function algorithmIdentifier(): AlgorithmIdentifier
    {
        return new RSAEncryptionAlgorithmIdentifier();
    }
    
    /**
     * Generate ASN.1 structure.
     *
     * @return Sequence
     */
    public function toASN1(): Sequence
    {
        return new Sequence(new Integer($this->_modulus),
            new Integer($this->_publicExponent));
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function toDER(): string
    {
        return $this->toASN1()->toDER();
    }
    
    /**
     * Generate PEM.
     *
     * @return PEM
     */
    public function toPEM(): PEM
    {
        return new PEM(PEM::TYPE_RSA_PUBLIC_KEY, $this->toDER());
    }
}
