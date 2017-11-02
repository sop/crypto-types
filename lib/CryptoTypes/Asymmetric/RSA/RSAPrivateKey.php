<?php

declare(strict_types=1);

namespace Sop\CryptoTypes\Asymmetric\RSA;

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\Integer;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKey;
use Sop\CryptoTypes\Asymmetric\PublicKey;

/**
 * Implements PKCS #1 RSAPrivateKey ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc2437#section-11.1.2
 */
class RSAPrivateKey extends PrivateKey
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
     * Private exponent.
     *
     * @var int|string $_privateExponent
     */
    protected $_privateExponent;
    
    /**
     * First prime factor.
     *
     * @var int|string $_prime1
     */
    protected $_prime1;
    
    /**
     * Second prime factor.
     *
     * @var int|string $_prime2
     */
    protected $_prime2;
    
    /**
     * First factor exponent.
     *
     * @var int|string $_exponent1
     */
    protected $_exponent1;
    
    /**
     * Second factor exponent.
     *
     * @var int|string $_exponent2
     */
    protected $_exponent2;
    
    /**
     * CRT coefficient of the second factor.
     *
     * @var int|string $_coefficient
     */
    protected $_coefficient;
    
    /**
     * Constructor.
     *
     * @param int|string $n Modulus
     * @param int|string $e Public exponent
     * @param int|string $d Private exponent
     * @param int|string $p First prime factor
     * @param int|string $q Second prime factor
     * @param int|string $dp First factor exponent
     * @param int|string $dq Second factor exponent
     * @param int|string $qi CRT coefficient of the second factor
     */
    public function __construct($n, $e, $d, $p, $q, $dp, $dq, $qi)
    {
        $this->_modulus = $n;
        $this->_publicExponent = $e;
        $this->_privateExponent = $d;
        $this->_prime1 = $p;
        $this->_prime2 = $q;
        $this->_exponent1 = $dp;
        $this->_exponent2 = $dq;
        $this->_coefficient = $qi;
    }
    
    /**
     * Initialize from ASN.1.
     *
     * @param Sequence $seq
     * @throws \UnexpectedValueException
     * @return self
     */
    public static function fromASN1(Sequence $seq)
    {
        $version = $seq->at(0)
            ->asInteger()
            ->number();
        if ($version != 0) {
            throw new \UnexpectedValueException("Version must be 0.");
        }
        // helper function get integer from given index
        $get_int = function ($idx) use ($seq) {
            return $seq->at($idx)
                ->asInteger()
                ->number();
        };
        $n = $get_int(1);
        $e = $get_int(2);
        $d = $get_int(3);
        $p = $get_int(4);
        $q = $get_int(5);
        $dp = $get_int(6);
        $dq = $get_int(7);
        $qi = $get_int(8);
        return new self($n, $e, $d, $p, $q, $dp, $dq, $qi);
    }
    
    /**
     * Initialize from DER data.
     *
     * @param string $data
     * @return self
     */
    public static function fromDER(string $data)
    {
        return self::fromASN1(Sequence::fromDER($data));
    }
    
    /**
     *
     * @see PrivateKey::fromPEM()
     * @param PEM $pem
     * @throws \UnexpectedValueException
     * @return self
     */
    public static function fromPEM(PEM $pem)
    {
        $pk = parent::fromPEM($pem);
        if (!($pk instanceof self)) {
            throw new \UnexpectedValueException("Not an RSA private key.");
        }
        return $pk;
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
     * Get private exponent.
     *
     * @return int|string
     */
    public function privateExponent()
    {
        return $this->_privateExponent;
    }
    
    /**
     * Get first prime factor.
     *
     * @return int|string
     */
    public function prime1()
    {
        return $this->_prime1;
    }
    
    /**
     * Get second prime factor.
     *
     * @return int|string
     */
    public function prime2()
    {
        return $this->_prime2;
    }
    
    /**
     * Get first factor exponent.
     *
     * @return int|string
     */
    public function exponent1()
    {
        return $this->_exponent1;
    }
    
    /**
     * Get second factor exponent.
     *
     * @return int|string
     */
    public function exponent2()
    {
        return $this->_exponent2;
    }
    
    /**
     * Get CRT coefficient of the second factor.
     *
     * @return int|string
     */
    public function coefficient()
    {
        return $this->_coefficient;
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function algorithmIdentifier(): \Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier
    {
        return new RSAEncryptionAlgorithmIdentifier();
    }
    
    /**
     *
     * {@inheritdoc}
     *
     * @return RSAPublicKey
     */
    public function publicKey(): PublicKey
    {
        return new RSAPublicKey($this->_modulus, $this->_publicExponent);
    }
    
    /**
     * Generate ASN.1 structure.
     *
     * @return Sequence
     */
    public function toASN1(): Sequence
    {
        return new Sequence(new Integer(0), new Integer($this->_modulus),
            new Integer($this->_publicExponent),
            new Integer($this->_privateExponent), new Integer($this->_prime1),
            new Integer($this->_prime2), new Integer($this->_exponent1),
            new Integer($this->_exponent2), new Integer($this->_coefficient));
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
     *
     * {@inheritdoc}
     *
     */
    public function toPEM(): PEM
    {
        return new PEM(PEM::TYPE_RSA_PRIVATE_KEY, $this->toDER());
    }
}
