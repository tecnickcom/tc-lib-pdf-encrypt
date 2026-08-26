<?php

/**
 * OutputTest.php
 *
 * @since     2011-05-23
 * @category  Library
 * @package   PdfEncrypt
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2011-2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-encrypt
 *
 * This file is part of tc-lib-pdf-encrypt software library.
 */

namespace Test;

/**
 * Output Test
 *
 * @since     2011-05-23
 * @category  Library
 * @package   PdfEncrypt
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2011-2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-encrypt
 */
class OutputTest extends TestUtil
{
    /** @param array<string,mixed> $data */
    protected function setRawEncryptData(OutputTestDouble $output, array $data): void
    {
        $property = new \ReflectionProperty(\Com\Tecnick\Pdf\Encrypt\Output::class, 'encryptdata');
        $property->setValue($output, $data);
    }

    /** @return array<string,mixed> */
    protected function getRawEncryptData(OutputTestDouble $output): array
    {
        $property = new \ReflectionProperty(\Com\Tecnick\Pdf\Encrypt\Output::class, 'encryptdata');
        /** @var array<string,mixed> */
        return $property->getValue($output);
    }

    protected function getOutputTestDouble(): OutputTestDouble
    {
        return new OutputTestDouble();
    }

    public function testGetPdfEncryptionObjZero(): void
    {
        $this->bcRunIgnoringUserDeprecations(function (): void {
            $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 0, ['print'], 'alpha', 'beta');
            $pon = 122;
            $result = $encrypt->getPdfEncryptionObj($pon);
            // Known-answer test: a fixed file ID and fixed passwords determine every byte.
            $expected =
                "123 0 obj\n"
                . "<<\n"
                . "/Filter /Standard\n"
                . "/V 1\n"
                . "/Length 40\n"
                . "/R 2\n"
                . "/O <0542fa0e15496869a825cd08c633ac10675c02167661241f5369895d768278b1>\n"
                . "/U <fb1b03dcf0158aae2cedf5b8a90aa9325b8bca8cb0d07d6b67b2b993402ac2f5>\n"
                . "/P -8\n"
                // EncryptMetadata is defined for V 4 and V 5 only.
                . ">>\n"
                . "endobj\n";
            $this->assertSame($expected, $result);
        });
    }

    /**
     * The O and U values of revision 3 were computed from ISO 32000-1
     * Algorithms 2, 3 and 5 independently of this library.
     */
    public function testGetPdfEncryptionObjOne(): void
    {
        $this->bcRunIgnoringUserDeprecations(function (): void {
            $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 1, ['print'], 'alpha', 'beta');
            $pon = 122;
            $result = $encrypt->getPdfEncryptionObj($pon);
            $expected =
                "123 0 obj\n"
                . "<<\n"
                . "/Filter /Standard\n"
                . "/V 2\n"
                . "/Length 128\n"
                . "/R 3\n"
                . "/O <8a270f21b879d1b085b290b9b7776208899d8f595c3b4af708a04f8d953e4fbd>\n"
                . "/U <9cf46567f9b0fbce65deca971ea9950800000000000000000000000000000000>\n"
                . "/P -8\n"
                . ">>\n"
                . "endobj\n";
            $this->assertSame($expected, $result);
        });
    }

    /** Revision 4 shares the revision 3 key derivation, and adds the crypt filter. */
    public function testGetPdfEncryptionObjTwo(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 2, ['print'], 'alpha', 'beta');
        $pon = 122;
        $result = $encrypt->getPdfEncryptionObj($pon);
        $expected =
            "123 0 obj\n"
            . "<<\n"
            . "/Filter /Standard\n"
            . "/V 4\n"
            . "/Length 128\n"
            . "/CF <<\n"
            . "/StdCF <<\n"
            . "/Type /CryptFilter\n"
            . "/CFM /AESV2\n"
            . "/AuthEvent /DocOpen\n"
            . "/Length 16\n"
            . ">>\n"
            . ">>\n"
            . "/StmF /StdCF\n"
            . "/StrF /StdCF\n"
            . "/EFF /StdCF\n"
            . "/R 4\n"
            . "/O <8a270f21b879d1b085b290b9b7776208899d8f595c3b4af708a04f8d953e4fbd>\n"
            . "/U <9cf46567f9b0fbce65deca971ea9950800000000000000000000000000000000>\n"
            . "/P -8\n"
            . "/EncryptMetadata true\n"
            . ">>\n"
            . "endobj\n";
        $this->assertSame($expected, $result);
    }

    /**
     * Revisions 5 and 6 draw two salts and four Perms bytes at random, so only
     * the shape of the dictionary is asserted here.
     */
    public function testGetPdfEncryptionObjThree(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 3, ['print'], 'alpha', 'beta');
        $pon = 122;
        $result = $encrypt->getPdfEncryptionObj($pon);
        $this->assertStringContainsString("/V 5\n", $result);
        $this->assertStringContainsString("/R 5\n", $result);
        $this->assertStringContainsString("/Length 256\n", $result);
        $this->assertStringContainsString("/CFM /AESV3\n", $result);
        $this->assertMatchesRegularExpression('~\n/O <[0-9a-f]{96}>\n~', $result);
        $this->assertMatchesRegularExpression('~\n/U <[0-9a-f]{96}>\n~', $result);
        $this->assertMatchesRegularExpression('~\n/OE <[0-9a-f]{64}>\n~', $result);
        $this->assertMatchesRegularExpression('~\n/UE <[0-9a-f]{64}>\n~', $result);
        $this->assertMatchesRegularExpression('~\n/Perms <[0-9a-f]{32}>\n~', $result);
        $this->assertStringContainsString("/P -8\n", $result);
    }

    /**
     * The whole revision 5 dictionary, with the random source pinned. Every entry
     * was computed from Adobe Extension Level 3 Algorithms 8, 9 and 10
     * independently of this library.
     */
    public function testGetPdfEncryptionObjThreeKnownAnswer(): void
    {
        $encrypt = new DeterministicEncrypt(true, \md5('kat'), 3, ['print'], 'userpass', 'ownerpass');
        $pon = 122;
        $expected =
            "123 0 obj\n"
            . "<<\n"
            . "/Filter /Standard\n"
            . "/V 5\n"
            . "/Length 256\n"
            . "/CF <<\n"
            . "/StdCF <<\n"
            . "/Type /CryptFilter\n"
            . "/CFM /AESV3\n"
            . "/AuthEvent /DocOpen\n"
            . "/Length 32\n"
            . ">>\n"
            . ">>\n"
            . "/StmF /StdCF\n"
            . "/StrF /StdCF\n"
            . "/EFF /StdCF\n"
            . "/R 5\n"
            . "/OE <24f81ea8781ae0e126667db5c4351419d251597e3f9fee39f7f7ad21345325e6>\n"
            . "/UE <f5bfc7e128b0aea23b4ad0e2574194e11fbbc94947f0fea507e09f1d9acbe46c>\n"
            . "/Perms <38f1dac54f2cf35705ac098dc8b2a14d>\n"
            . '/O <261f93fb622fcb5e99e93373fd19f130a306f0037e03d3163ce6715ecad1ffd0'
            . "2942b99da77429eeb86767ec1bde925b>\n"
            . '/U <4cd31bbdb787ed5fb722903e1e122e151af8039e43c67f5e134f5f0747a59e6f'
            . "036fa5b2d8027e443eb32a70dace7de8>\n"
            . "/P -8\n"
            . "/EncryptMetadata true\n"
            . ">>\n"
            . "endobj\n";
        $this->assertSame($expected, $encrypt->getPdfEncryptionObj($pon));
    }

    /** The same for revision 6, whose password hash is Algorithm 2.B. */
    public function testGetPdfEncryptionObjFourKnownAnswer(): void
    {
        $encrypt = new DeterministicEncrypt(true, \md5('kat'), 4, ['print'], 'userpass', 'ownerpass');
        $pon = 122;
        $expected =
            "123 0 obj\n"
            . "<<\n"
            . "/Filter /Standard\n"
            . "/V 5\n"
            . "/Length 256\n"
            . "/CF <<\n"
            . "/StdCF <<\n"
            . "/Type /CryptFilter\n"
            . "/CFM /AESV3\n"
            . "/AuthEvent /DocOpen\n"
            . "/Length 32\n"
            . ">>\n"
            . ">>\n"
            . "/StmF /StdCF\n"
            . "/StrF /StdCF\n"
            . "/EFF /StdCF\n"
            . "/R 6\n"
            . "/OE <3ee1df3ccf3b3beca5339bd9ba51042ab35c3624716ba4c0a2b492e361fcb3e3>\n"
            . "/UE <dce9d292203c654986b17e371129e548aba22d46114d2e7572b29ee152f67f93>\n"
            . "/Perms <38f1dac54f2cf35705ac098dc8b2a14d>\n"
            . '/O <0beb921148d38493a586e9c952b29673c5fe1fd883d51c6a722d8a0120318cff'
            . "2942b99da77429eeb86767ec1bde925b>\n"
            . '/U <f770972a5cf0392377860a6e6d466e55065d033119834d858f7916d90d710710'
            . "036fa5b2d8027e443eb32a70dace7de8>\n"
            . "/P -8\n"
            . "/EncryptMetadata true\n"
            . ">>\n"
            . "endobj\n";
        $this->assertSame($expected, $encrypt->getPdfEncryptionObj($pon));
    }

    /**
     * A public-key dictionary carries the recipient envelopes instead of the
     * O, U and P entries of the standard handler.
     */
    public function testGetPdfEncryptionObjThreePub(): void
    {
        $pubkeys = [[
            'c' => __DIR__ . '/data/cert.pem',
            'p' => ['print'],
        ]];
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 3, pubkeys: $pubkeys);
        $pon = 122;
        $result = $encrypt->getPdfEncryptionObj($pon);
        $this->assertStringContainsString("/Filter /Adobe.PubSec\n", $result);
        $this->assertStringContainsString("/SubFilter /adbe.pkcs7.s5\n", $result);
        $this->assertStringContainsString("/V 5\n", $result);
        $this->assertStringContainsString("/StmF /DefaultCryptFilter\n", $result);
        $this->assertMatchesRegularExpression('~\n/Recipients \[ <[0-9a-f]+> \]\n~', $result);
        $this->assertStringNotContainsString('/O <', $result);
        $this->assertStringNotContainsString('/U <', $result);
        $this->assertStringNotContainsString('/P ', $result);
    }

    /** Below V 4 the recipients live in the dictionary itself, not in a crypt filter. */
    public function testGetPdfEncryptionObjOnePub(): void
    {
        $this->bcRunIgnoringUserDeprecations(function (): void {
            $pubkeys = [[
                'c' => __DIR__ . '/data/cert.pem',
                'p' => ['print'],
            ]];
            $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 1, pubkeys: $pubkeys);
            $pon = 122;
            $result = $encrypt->getPdfEncryptionObj($pon);
            $this->assertStringContainsString("/Filter /Adobe.PubSec\n", $result);
            $this->assertStringContainsString("/SubFilter /adbe.pkcs7.s4\n", $result);
            $this->assertStringContainsString("/V 2\n", $result);
            $this->assertStringNotContainsString('/CF <<', $result);
            $this->assertMatchesRegularExpression('~\n /Recipients \[ <[0-9a-f]+> \]\n~', $result);
        });
    }

    public function testGetPdfEncryptionObjFour(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 4, ['print'], 'alpha', 'beta');
        $pon = 122;
        $result = $encrypt->getPdfEncryptionObj($pon);
        $this->assertStringContainsString('/V 5', $result);
        $this->assertStringContainsString('/R 6', $result);
        $this->assertStringContainsString('/Length 256', $result);
        $this->assertMatchesRegularExpression('~\n/O <[0-9a-f]{96}>\n~', $result);
        $this->assertMatchesRegularExpression('~\n/U <[0-9a-f]{96}>\n~', $result);
        $this->assertMatchesRegularExpression('~\n/Perms <[0-9a-f]{32}>\n~', $result);
    }

    /** /EFF points at the stream filter when embedded file encryption is enabled. */
    public function testGetPdfEncryptionObjEff(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(
            true,
            \md5('file_id'),
            2,
            ['print'],
            'alpha',
            'beta',
            null,
            true, // encryptMetadata
            true, // encryptEmbeddedFiles
        );
        $pon = 0;
        $result = $encrypt->getPdfEncryptionObj($pon);
        $this->assertStringContainsString('/EFF /StdCF', $result);
    }

    /**
     * /EFF is written as /Identity when embedded file encryption is disabled:
     * ISO 32000-1 section 7.6.1 makes an absent /EFF mean /StmF.
     */
    public function testGetPdfEncryptionObjNoEff(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(
            true,
            \md5('file_id'),
            2,
            ['print'],
            'alpha',
            'beta',
            null,
            true, // encryptMetadata
            false, // encryptEmbeddedFiles = false
        );
        $pon = 0;
        $result = $encrypt->getPdfEncryptionObj($pon);
        $this->assertStringContainsString("/EFF /Identity\n", $result);
    }

    /** The /EFF entry is defined for V 4 and V 5 only, so below that it is absent. */
    public function testGetPdfEncryptionObjNoEffBelowVersionFour(): void
    {
        $this->bcRunIgnoringUserDeprecations(function (): void {
            $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(
                true,
                \md5('file_id'),
                1,
                ['print'],
                'alpha',
                'beta',
                null,
                true,
                false,
            );
            $pon = 0;
            $this->assertStringNotContainsString('/EFF', $encrypt->getPdfEncryptionObj($pon));
        });
    }

    /** EncryptMetadata=false appears in standard-mode output. */
    public function testGetPdfEncryptionObjEncryptMetadataFalse(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(
            true,
            \md5('file_id'),
            3,
            ['print'],
            'alpha',
            'beta',
            null,
            false, // encryptMetadata = false
        );
        $pon = 0;
        $result = $encrypt->getPdfEncryptionObj($pon);
        $this->assertStringContainsString('/EncryptMetadata false', $result);
    }

    /** EncryptMetadata=true, the default, appears in standard-mode output. */
    public function testGetPdfEncryptionObjEncryptMetadataTrue(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 3, ['print'], 'alpha', 'beta');
        $pon = 0;
        $result = $encrypt->getPdfEncryptionObj($pon);
        $this->assertStringContainsString('/EncryptMetadata true', $result);
    }

    /** Mode 4 public-key output carries the Recipients array. */
    public function testGetPdfEncryptionObjFourPub(): void
    {
        $pubkeys = [[
            'c' => __DIR__ . '/data/cert.pem',
            'p' => ['print'],
        ]];
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 4, pubkeys: $pubkeys);
        $pon = 122;
        $result = $encrypt->getPdfEncryptionObj($pon);
        $this->assertStringContainsString("/V 5\n", $result);
        $this->assertStringContainsString("/CFM /AESV3\n", $result);
        $this->assertMatchesRegularExpression('~\n/Recipients \[ <[0-9a-f]+> \]\n~', $result);
        $this->assertStringContainsString("/EncryptMetadata true\n", $result);
    }

    /** Each recipient contributes one entry to the Recipients array, in order. */
    public function testGetPdfEncryptionObjListsEveryRecipient(): void
    {
        $pubkeys = [
            ['c' => __DIR__ . '/data/cert.pem', 'p' => ['print']],
            ['c' => __DIR__ . '/data/cert2.pem', 'p' => ['copy']],
        ];
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 3, pubkeys: $pubkeys);
        $pon = 0;
        $result = $encrypt->getPdfEncryptionObj($pon);

        $recipients = $encrypt->getEncryptionData()['Recipients'];
        $this->assertCount(2, $recipients);
        $expected = '/Recipients [ <' . ($recipients[0] ?? '') . '> <' . ($recipients[1] ?? '') . "> ]\n";
        $this->assertStringContainsString($expected, $result);
    }

    public function testSetMissingValuesCopiesEncryptMetadataFalseToCf(): void
    {
        $output = $this->getOutputTestDouble();
        $data = $this->getRawEncryptData($output);
        if (!isset($data['CF']) || !\is_array($data['CF'])) {
            $this->fail('Missing CF array in encryptdata');
        }

        /** @var array<string,mixed> $cfData */
        $cfData = $data['CF'];
        $data['EncryptMetadata'] = false;
        $cfData['EncryptMetadata'] = true;
        $data['CF'] = $cfData;
        $this->setRawEncryptData($output, $data);

        $output->callSetMissingValues();

        $result = $this->getRawEncryptData($output);
        if (!isset($result['CF']) || !\is_array($result['CF'])) {
            $this->fail('Missing CF array in encryptdata');
        }

        /** @var array<string,mixed> $cfData */
        $cfData = $result['CF'];
        if (!\array_key_exists('EncryptMetadata', $cfData) || !\is_bool($cfData['EncryptMetadata'])) {
            $this->fail('Missing boolean EncryptMetadata in CF array');
        }

        $this->assertFalse($cfData['EncryptMetadata']);
    }

    public function testSetMissingValuesCopiesEncryptMetadataTrueToCf(): void
    {
        $output = $this->getOutputTestDouble();
        $data = $this->getRawEncryptData($output);
        if (!isset($data['CF']) || !\is_array($data['CF'])) {
            $this->fail('Missing CF array in encryptdata');
        }

        /** @var array<string,mixed> $cfData */
        $cfData = $data['CF'];
        $data['EncryptMetadata'] = true;
        $cfData['EncryptMetadata'] = false;
        $data['CF'] = $cfData;
        $this->setRawEncryptData($output, $data);

        $output->callSetMissingValues();

        $result = $this->getRawEncryptData($output);
        if (!isset($result['CF']) || !\is_array($result['CF'])) {
            $this->fail('Missing CF array in encryptdata');
        }

        /** @var array<string,mixed> $cfData */
        $cfData = $result['CF'];
        if (!\array_key_exists('EncryptMetadata', $cfData) || !\is_bool($cfData['EncryptMetadata'])) {
            $this->fail('Missing boolean EncryptMetadata in CF array');
        }

        $this->assertTrue($cfData['EncryptMetadata']);
    }
}
