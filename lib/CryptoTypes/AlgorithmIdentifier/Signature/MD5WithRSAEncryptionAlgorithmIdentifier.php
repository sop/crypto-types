<?php

namespace Sop\CryptoTypes\AlgorithmIdentifier\Signature;

/**
 * RSA with MD5 signature algorithm identifier.
 *
 * @link https://tools.ietf.org/html/rfc3279#section-2.2.1
 */
class MD5WithRSAEncryptionAlgorithmIdentifier extends RFC3279RSASignatureAlgorithmIdentifier
{
    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->_oid = self::OID_MD5_WITH_RSA_ENCRYPTION;
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function name()
    {
        return "md5WithRSAEncryption";
    }
}
