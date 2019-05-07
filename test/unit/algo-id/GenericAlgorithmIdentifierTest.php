<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 *
 * @internal
 */
class GenericAlgorithmIdentifierTest extends TestCase
{
    public function testCreate()
    {
        $ai = new GenericAlgorithmIdentifier('1.3.6.1.3',
            new UnspecifiedType(new Integer(42)));
        $this->assertInstanceOf(GenericAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends testCreate
     *
     * @param GenericAlgorithmIdentifier $ai
     */
    public function testName(GenericAlgorithmIdentifier $ai)
    {
        $this->assertEquals('1.3.6.1.3', $ai->name());
    }

    /**
     * @depends testCreate
     *
     * @param GenericAlgorithmIdentifier $ai
     */
    public function testParameters(GenericAlgorithmIdentifier $ai)
    {
        $this->assertInstanceOf(UnspecifiedType::class, $ai->parameters());
    }

    /**
     * @depends testCreate
     *
     * @param GenericAlgorithmIdentifier $ai
     */
    public function testEncode(GenericAlgorithmIdentifier $ai)
    {
        $this->assertInstanceOf(Sequence::class, $ai->toASN1());
    }
}
