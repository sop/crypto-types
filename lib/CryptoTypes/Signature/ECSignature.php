<?php

namespace Sop\CryptoTypes\Signature;

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\BitString;
use ASN1\Type\Primitive\Integer;

/**
 * Implements ECDSA signature value.
 *
 * ECDSA signature is represented as a <code>ECDSA-Sig-Value</code> ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc3278#section-8.2
 */
class ECSignature extends Signature
{
    /**
     * r-value.
     *
     * @var int|string $_r
     */
    protected $_r;
    
    /**
     * s-value.
     *
     * @var int|string $_s
     */
    protected $_s;
    
    /**
     * Constructor.
     *
     * @param int|string $r Signature's <code>r</code> value
     * @param int|string $s Signature's <code>s</code> value
     */
    public function __construct($r, $s)
    {
        $this->_r = $r;
        $this->_s = $s;
    }
    
    /**
     * Initialize from ASN.1.
     *
     * @param Sequence $seq
     * @return self
     */
    public static function fromASN1(Sequence $seq)
    {
        $r = $seq->at(0)
            ->asInteger()
            ->number();
        $s = $seq->at(1)
            ->asInteger()
            ->number();
        return new self($r, $s);
    }
    
    /**
     * Initialize from DER.
     *
     * @param string $data
     * @return self
     */
    public static function fromDER($data)
    {
        return self::fromASN1(Sequence::fromDER($data));
    }
    
    /**
     * Get the r-value.
     *
     * @return int|string
     */
    public function r()
    {
        return $this->_r;
    }
    
    /**
     * Get the s-value.
     *
     * @return int|string
     */
    public function s()
    {
        return $this->_s;
    }
    
    /**
     * Generate ASN.1 structure.
     *
     * @return Sequence
     */
    public function toASN1()
    {
        return new Sequence(new Integer($this->_r), new Integer($this->_s));
    }
    
    /**
     * Get DER encoding of the signature.
     *
     * @return string
     */
    public function toDER()
    {
        return $this->toASN1()->toDER();
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function bitString()
    {
        return new BitString($this->toDER());
    }
}
