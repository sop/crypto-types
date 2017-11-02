<?php
declare(strict_types=1);

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\ObjectIdentifier;
use ASN1\Type\UnspecifiedType;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifierFactory;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifierProvider;
use Sop\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 */
class AIFactoryTest extends PHPUnit_Framework_TestCase
{
    /**
     */
    public function testProvider()
    {
        $factory = new AlgorithmIdentifierFactory(new AIFactoryTest_Provider());
        $seq = new Sequence(new ObjectIdentifier("1.3.6.1.3"));
        $ai = $factory->parse($seq);
        $this->assertInstanceOf(AIFactoryTest_CustomAlgo::class, $ai);
    }
    
    /**
     */
    public function testProviderNoMatch()
    {
        $factory = new AlgorithmIdentifierFactory(new AIFactoryTest_Provider());
        $seq = new Sequence(new ObjectIdentifier("1.3.6.1.3.1"));
        $ai = $factory->parse($seq);
        $this->assertNotInstanceOf(AIFactoryTest_CustomAlgo::class, $ai);
    }
}

class AIFactoryTest_Provider implements AlgorithmIdentifierProvider
{
    public function supportsOID(string $oid): bool
    {
        return "1.3.6.1.3" == $oid;
    }
    public function getClassByOID(string $oid): string
    {
        return AIFactoryTest_CustomAlgo::class;
    }
}

class AIFactoryTest_CustomAlgo extends SpecificAlgorithmIdentifier
{
    public static function fromASN1Params(UnspecifiedType $params = null)
    {
        return new self();
    }
    public function name(): string
    {
        return "";
    }
    protected function _paramsASN1()
    {
        return null;
    }
}
