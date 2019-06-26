<?php

declare(strict_types = 1);

namespace Sop\CryptoTypes\Asymmetric\RFC8410;

use Sop\ASN1\Type\Primitive\OctetString;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\PrivateKey;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;

/**
 * Implements an intermediary object to store a private key using
 * Curve25519 or Curve448 as defined by RFC 8410.
 *
 * Private keys described in RFC 8410 may only be encoded as `OneAsymmetricKey`.
 *
 * @see https://tools.ietf.org/html/rfc8410
 */
abstract class RFC8410PrivateKey extends PrivateKey
{
    /**
     * Private key data.
     *
     * @var string
     */
    protected $_privateKeyData;

    /**
     * Public key data.
     *
     * @var null|string
     */
    protected $_publicKeyData;

    /**
     * Constructor.
     *
     * @param string      $private_key Private key data
     * @param null|string $public_key  Public key data
     */
    public function __construct(string $private_key, ?string $public_key = null)
    {
        $this->_privateKeyData = $private_key;
        $this->_publicKeyData = $public_key;
    }

    /**
     * Initialize from `CurvePrivateKey` OctetString.
     *
     * @param OctetString $str        Private key data wrapped into OctetString
     * @param null|string $public_key Optional public key data
     */
    public static function fromOctetString(OctetString $str,
        ?string $public_key = null): self
    {
        return new static($str->string(), $public_key);
    }

    /**
     * {@inheritdoc}
     */
    public function privateKeyData(): string
    {
        return $this->_privateKeyData;
    }

    /**
     * Whether public key is set.
     *
     * @return bool
     */
    public function hasPublicKey(): bool
    {
        return isset($this->_publicKeyData);
    }

    /**
     * Generate ASN.1 structure.
     *
     * @return OctetString
     */
    public function toASN1(): OctetString
    {
        return new OctetString($this->_privateKeyData);
    }

    /**
     * {@inheritdoc}
     */
    public function toDER(): string
    {
        return $this->toASN1()->toDER();
    }

    /**
     * {@inheritdoc}
     */
    public function toPEM(): PEM
    {
        $pki = new PrivateKeyInfo($this->algorithmIdentifier(),
            $this->toDER(), null, $this->_publicKeyData);
        return $pki->toPEM();
    }
}
