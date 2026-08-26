<?php

/**
 * EncryptTest.php
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
 * Encrypt Test
 *
 * @since     2011-05-23
 * @category  Library
 * @package   PdfEncrypt
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2011-2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-encrypt
 */
class EncryptTest extends TestUtil
{
    /**
     * Recipient certificate used by the public-key tests.
     */
    private const CERT = __DIR__ . '/data/cert.pem';

    public function testEncryptException(): void
    {
        $this->bcRunIgnoringUserDeprecations(function (): void {
            $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
            $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'));
            $encrypt->encrypt('WRONG');
        });
    }

    public function testEncryptModeException(): void
    {
        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 5);
    }

    public function testEncryptThree(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 3, ['print'], 'alpha', 'beta');
        $result = $encrypt->encrypt(3, 'alpha');
        $this->assertEquals(32, \strlen($result));
    }

    public function testEncryptWithAesEncoderName(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 3, ['print'], 'alpha', 'beta');
        $result = $encrypt->encrypt('AES', 'alpha', '0123456789abcdef0123456789abcdef');
        $this->assertGreaterThan(16, \strlen($result));
    }

    public function testEncryptPubThree(): void
    {
        $pubkeys = [[
            'c' => self::CERT,
            'p' => ['print'],
        ]];
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 3, pubkeys: $pubkeys);
        $result = $encrypt->encrypt(3, 'alpha');
        $this->assertEquals(32, \strlen($result));
    }

    /** A recipient without a 'p' entry is granted every permission. */
    public function testEncryptPubNoP(): void
    {
        $pubkeys = [[
            'c' => self::CERT,
        ]];
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 3, pubkeys: $pubkeys);
        $this->assertCount(1, $encrypt->getEncryptionData()['Recipients']);

        $dec = new \Com\Tecnick\Pdf\Encrypt\Decrypt($encrypt->getEncryptionData());
        $this->assertTrue($dec->authenticate('', self::CERT));
        // -4 is the P value with every permission granted.
        $this->assertSame(-4, $dec->getRecipientPermissions());
    }

    /** A file that is not a certificate is refused by openssl_pkcs7_encrypt(). */
    public function testEncryptPubException(): void
    {
        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class, 'Unable to encrypt the file');
        new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 3, pubkeys: [[
            'c' => __FILE__,
            'p' => ['print'],
        ]]);
    }

    public function testEncryptPubUnreadableCertificateException(): void
    {
        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class, 'Unable to read public key file');

        \set_error_handler(static fn(): bool => true);
        try {
            new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 3, pubkeys: [[
                'c' => __DIR__ . '/data/does-not-exist.pem',
                'p' => ['print'],
            ]]);
        } finally {
            \restore_error_handler();
        }
    }

    /** Public-key mode warns when a password is supplied. */
    public function testPublicKeyModeWarnsAboutIgnoredPasswords(): void
    {
        $this->bcAssertUserWarningMessageMatches('/Public-key encryption ignores the user and owner passwords/', function (): void {
            $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 3, user_pass: 'alpha', pubkeys: [[
                'c' => self::CERT,
                'p' => ['print'],
            ]]);
            $this->assertSame('', $encrypt->getEncryptionData()['U']);
        });
    }

    /** Public-key mode warns when the permissions argument is supplied. */
    public function testPublicKeyModeWarnsAboutIgnoredPermissions(): void
    {
        $this->bcAssertUserWarningMessageMatches('/Public-key encryption ignores the permissions argument/', function (): void {
            $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(
                true,
                \md5('file_id'),
                3,
                ['print'],
                pubkeys: [['c' => self::CERT, 'p' => ['print']]],
            );
            $this->assertSame(0, $encrypt->getEncryptionData()['P']);
        });
    }

    /** The default arguments raise no public-key warning. */
    public function testPublicKeyModeIsSilentWithoutIgnoredArguments(): void
    {
        $warnings = [];
        \set_error_handler(static function (int $errno, string $errstr) use (&$warnings): bool {
            if ($errno === E_USER_WARNING) {
                $warnings[] = $errstr;
            }

            return $errno === E_USER_WARNING || $errno === E_USER_DEPRECATED;
        });

        try {
            new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 3, pubkeys: [
                ['c' => self::CERT, 'p' => ['print']],
            ]);
        } finally {
            \restore_error_handler();
        }

        $this->assertSame([], $warnings);
    }

    public function testEncryptRc4(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 3, ['print'], 'alpha', 'beta');
        $result = $encrypt->encrypt('RC4', 'alpha', '0123456789abcdef');
        $this->assertSame(5, \strlen($result));
    }

    public function testEncryptModZeroPub(): void
    {
        $this->bcRunIgnoringUserDeprecations(function (): void {
            $pubkeys = [[
                'c' => self::CERT,
                'p' => ['print'],
            ]];
            $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 0, pubkeys: $pubkeys);
            $result = $encrypt->encrypt(1, 'alpha');
            $this->assertEquals(5, \strlen($result));
        });
    }

    /** RC4 mode 0 emits a deprecation notice. */
    public function testRc4DeprecationModeZero(): void
    {
        $this->bcAssertUserDeprecationMessageMatches('/RC4 encryption.*deprecated.*cryptographically broken/i', function (): void {
            $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 0, ['print'], 'alpha', 'beta');
            $result = $encrypt->encrypt(0, 'alpha');
            $this->assertGreaterThan(0, \strlen($result));
        });
    }

    /** RC4 mode 1 emits a deprecation notice. */
    public function testRc4DeprecationModeOne(): void
    {
        $this->bcAssertUserDeprecationMessageMatches('/RC4 encryption.*deprecated.*cryptographically broken/i', function (): void {
            $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 1, ['print'], 'alpha', 'beta');
            $result = $encrypt->encrypt(1, 'alpha');
            $this->assertGreaterThan(0, \strlen($result));
        });
    }

    /**
     * @return array<string, array{mixed, string}>
     */
    public static function malformedRecipientProvider(): array
    {
        return [
            'not an array' => ['cert.pem', 'each recipient must be an array'],
            'no certificate' => [[], "the 'c' entry must be a non-empty certificate path"],
            'empty certificate' => [['c' => ''], "the 'c' entry must be a non-empty certificate path"],
            'certificate not a string' => [['c' => 123], "the 'c' entry must be a non-empty certificate path"],
            'permissions not an array' => [
                ['c' => 'test/data/cert.pem', 'p' => 'print'],
                "the 'p' entry must be an array of permission names",
            ],
            'permission not a string' => [
                ['c' => 'test/data/cert.pem', 'p' => [7]],
                "every 'p' entry must be a permission name",
            ],
        ];
    }

    /** A malformed recipient entry is rejected with a message naming the fault. */
    #[\PHPUnit\Framework\Attributes\DataProvider('malformedRecipientProvider')]
    public function testMalformedRecipientIsRejected(mixed $recipient, string $message): void
    {
        // The value is deliberately outside the declared parameter shape.
        /** @var list<array{'c': string, 'p'?: array<string>}> $pubkeys */
        $pubkeys = [$recipient];

        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class, 'recipient 0: ' . $message);
        new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, '', 2, pubkeys: $pubkeys);
    }

    /** The message names the position of the offending entry. */
    public function testMalformedRecipientNamesItsPosition(): void
    {
        $this->bcExpectException(
            \Com\Tecnick\Pdf\Encrypt\Exception::class,
            "recipient 1: the 'c' entry must be a non-empty certificate path",
        );
        new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, '', 2, pubkeys: [
            ['c' => 'test/data/cert.pem'],
            ['c' => ''],
        ]);
    }

    /** Mode 0 with pubkeys emits the upgrade deprecation notice. */
    public function testPubKeyModeZeroDeprecation(): void
    {
        $this->bcAssertUserDeprecationMessageMatches('/Public-key encryption requires at least RC4-128/i', function (): void {
            $pubkeys = [[
                'c' => self::CERT,
                'p' => ['print'],
            ]];
            $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 0, pubkeys: $pubkeys);
            // The encryption data reports the promoted mode.
            $data = $encrypt->getEncryptionData();
            $this->assertEquals(1, $data['mode']);
            $this->assertEquals(2, $data['V']);
        });
    }

    /** The AES-256 Perms bytes 12 to 15 are random. */
    public function testPermsRandomBytes(): void
    {
        $encrypt1 = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 3, ['print'], 'alpha', 'beta');
        $encrypt2 = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 3, ['print'], 'alpha', 'beta');
        $data1 = $encrypt1->getEncryptionData();
        $data2 = $encrypt2->getEncryptionData();
        // The perms block is 16 bytes of AES output, with no padding block.
        $this->assertEquals(16, \strlen($data1['perms']));
        $this->assertEquals(16, \strlen($data2['perms']));
        // Bytes 12 to 15 are random, so two blocks collide with probability 2^-32.
        $this->assertNotEquals($data1['perms'], $data2['perms'], 'perms bytes should be random each time');
    }

    /** AES-256 with EncryptMetadata=false stores the flag. */
    public function testEncryptMetadataFalse(): void
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
        $data = $encrypt->getEncryptionData();
        $this->assertFalse($data['EncryptMetadata']);
    }

    /**
     * ISO 32000-1 Table 21 defines EncryptMetadata for V 4 and V 5 only, so for
     * the RC4 modes the request is refused with a warning.
     *
     * @param int<0, 1> $mode
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('rc4ModeProvider')]
    public function testEncryptMetadataFalseIsRefusedForRc4Modes(int $mode): void
    {
        $this->bcAssertUserWarningMessageMatches('/Unencrypted metadata requires AES/', function () use ($mode): void {
            $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(
                true,
                \md5('file_id'),
                $mode,
                ['print'],
                'alpha',
                'beta',
                null,
                false,
            );
            $this->assertTrue($encrypt->getEncryptionData()['EncryptMetadata']);
        });
    }

    /**
     * @return array<string, array{int<0, 1>}>
     */
    public static function rc4ModeProvider(): array
    {
        return [
            'mode 0' => [0],
            'mode 1' => [1],
        ];
    }

    /** The default value raises no warning for the RC4 modes. */
    public function testEncryptMetadataTrueIsSilentForRc4Modes(): void
    {
        $warnings = [];
        \set_error_handler(static function (int $errno, string $errstr) use (&$warnings): bool {
            if ($errno === E_USER_WARNING) {
                $warnings[] = $errstr;
            }

            return $errno === E_USER_WARNING || $errno === E_USER_DEPRECATED;
        });

        try {
            new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 0, ['print'], 'alpha', 'beta');
        } finally {
            \restore_error_handler();
        }

        $this->assertSame([], $warnings);
    }

    /**
     * The EncryptMetadata entry is not written below V 4.
     *
     * @param int<0, 1> $mode
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('rc4ModeProvider')]
    public function testEncryptMetadataEntryIsOmittedBelowVersionFour(int $mode): void
    {
        $this->bcRunIgnoringUserNotices(function () use ($mode): void {
            $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), $mode, ['print'], 'alpha', 'beta');
            $pon = 0;
            $this->assertStringNotContainsString('/EncryptMetadata', $encrypt->getPdfEncryptionObj($pon));
        });
    }

    /**
     * @return array<string, array{int<2, 4>}>
     */
    public static function aesModeProvider(): array
    {
        return [
            'mode 2' => [2],
            'mode 3' => [3],
            'mode 4' => [4],
        ];
    }

    /** From V 4 up the EncryptMetadata entry is always written. */
    #[\PHPUnit\Framework\Attributes\DataProvider('aesModeProvider')]
    public function testEncryptMetadataEntryIsWrittenFromVersionFour(int $mode): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), $mode, ['print'], 'alpha', 'beta');
        $pon = 0;
        $this->assertStringContainsString('/EncryptMetadata true', $encrypt->getPdfEncryptionObj($pon));
    }

    /** AES-256 R6 (mode 4) encrypt round-trip. */
    public function testEncryptFour(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 4, ['print'], 'alpha', 'beta');
        $result = $encrypt->encrypt(4, 'alpha');
        $this->assertEquals(32, \strlen($result));
    }

    /** AES-256 R6 (mode 4) reports V 5, R 6 and mode 4. */
    public function testEncryptFourSettings(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 4, ['print'], 'alpha', 'beta');
        $data = $encrypt->getEncryptionData();
        $this->assertEquals(4, $data['mode']);
        $this->assertEquals(5, $data['V']);
        $this->assertEquals(6, $data['R']);
        $this->assertEquals(256, $data['Length']);
        $this->assertEquals('AESV3', $data['CF']['CFM']);
        $this->assertEquals(48, \strlen($data['U']));
        $this->assertEquals(48, \strlen($data['O']));
        $this->assertEquals(32, \strlen($data['UE']));
        $this->assertEquals(32, \strlen($data['OE']));
        $this->assertEquals(16, \strlen($data['perms']));
    }

    /** An empty file ID is replaced by a random 16-byte one. */
    public function testEmptyFileIdIsGenerated(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, '', 2, ['print']);
        $data = $encrypt->getEncryptionData();
        $this->assertEquals(16, \strlen($data['fileid']));
        $this->assertEquals(4, $data['R']);
    }

    /** AES-256 R6 (mode 4) public-key encryption. */
    public function testEncryptPubFour(): void
    {
        $pubkeys = [[
            'c' => self::CERT,
            'p' => ['print'],
        ]];
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 4, pubkeys: $pubkeys);
        $result = $encrypt->encrypt(4, 'alpha');
        $this->assertEquals(32, \strlen($result));
    }

    public function testGetEncryptionData(): void
    {
        $this->bcRunIgnoringUserDeprecations(function (): void {
            $permissions = ['print'];
            $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 0, $permissions, 'alpha', 'beta');
            $result = $encrypt->getEncryptionData();
            $this->assertSame(-8, $result['protection']);
            $this->assertEquals(1, $result['V']);
            $this->assertEquals(40, $result['Length']);
            $this->assertEquals('V2', $result['CF']['CFM']);
        });
    }

    public function testGetObjectKey(): void
    {
        $permissions = ['print', 'modify', 'copy', 'annot-forms', 'fill-forms', 'extract', 'assemble', 'print-high'];

        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 2, $permissions, 'alpha', 'beta');
        $result = $encrypt->getObjectKey(123);
        $this->assertSame('a47d6307868ba078a7bf96531d64fa64', \bin2hex($result));
    }

    public function testGetUserPermissionCode(): void
    {
        $permissions = [
            'owner',
            'print',
            'modify',
            'copy',
            'annot-forms',
            'fill-forms',
            'extract',
            'assemble',
            'print-high',
        ];

        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt();
        $result = $encrypt->getUserPermissionCode($permissions, 0);
        $this->assertSame(-62, $result);
    }

    /** An unrecognised permission name is rejected. */
    public function testGetUserPermissionCodeRejectsInvalidPermission(): void
    {
        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt();
        $encrypt->getUserPermissionCode(['invalid-permission'], 0);
    }

    /** No blocked permission yields the P value with everything granted. */
    public function testGetUserPermissionCodeDefault(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt();
        $this->assertSame(-4, $encrypt->getUserPermissionCode([], 4));
    }

    /** Repeating a permission yields the same P value. */
    public function testGetUserPermissionCodeIsIdempotent(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt();
        $once = $encrypt->getUserPermissionCode(['print'], 4);
        $twice = $encrypt->getUserPermissionCode(['print', 'print'], 4);
        $this->assertSame($once, $twice);
        // bit 3 (print) cleared, bit 4 (modify) still granted
        $this->assertSame(0, $once & 4);
        $this->assertSame(8, $once & 8);
    }

    /** Each permission name clears its own bit and no other. */
    public function testGetUserPermissionCodeEachBit(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt();
        $bits = [
            'print' => 4,
            'modify' => 8,
            'copy' => 16,
            'annot-forms' => 32,
            'fill-forms' => 256,
            'extract' => 512,
            'assemble' => 1024,
            'print-high' => 2048,
        ];
        foreach ($bits as $name => $bit) {
            $result = $encrypt->getUserPermissionCode([$name], 4);
            $this->assertSame(0, $result & $bit, $name . ' must be cleared');
            $this->assertSame(-4 & ~$bit, $result, $name . ' must clear only its own bit');
        }
    }

    /** Bit 2 uses inverted logic: naming 'owner' sets it. */
    public function testGetUserPermissionCodeOwnerBit(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt();
        $this->assertSame(0, $encrypt->getUserPermissionCode([], 4) & 2);
        $this->assertSame(2, $encrypt->getUserPermissionCode(['owner'], 4) & 2);
    }

    /** Revision 2 defines bits 3 to 6 only; the others stay granted. */
    public function testGetUserPermissionCodeRevisionTwoIgnoresHighBits(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt();
        $result = $encrypt->getUserPermissionCode(['print-high'], 0);
        $this->assertSame(-4, $result);
    }

    /** A non-hexadecimal file ID is rejected. */
    public function testInvalidFileIdThrows(): void
    {
        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, 'ZZZZ-not-hex', 2, ['print'], 'alpha', 'beta');
    }

    /** Dumping the object reveals neither the file key nor the passwords. */
    public function testDebugInfoRedactsSecrets(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 4, ['print'], 'alpha', 'beta');
        $dump = \print_r($encrypt->__debugInfo(), true);
        $this->assertStringNotContainsString('alpha', $dump);
        $this->assertStringNotContainsString('beta', $dump);
        $this->assertStringNotContainsString(\bin2hex($encrypt->getEncryptionData()['key']), \bin2hex($dump));
        $this->assertStringContainsString('[redacted]', $dump);
    }

    /** An encryption dictionary is produced only when encryption is enabled. */
    public function testGetPdfEncryptionObjDisabledThrows(): void
    {
        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt();
        $pon = 0;
        $encrypt->getPdfEncryptionObj($pon);
    }

    public function testConvertHexStringToString(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt();

        $result = $encrypt->convertHexStringToString('');
        $this->assertEquals('', $result);

        $result = $encrypt->convertHexStringToString('68656c6c6f20776f726c64');
        $this->assertEquals('hello world', $result);
    }

    /** An odd-length hexadecimal input is rejected. */
    public function testConvertHexStringToStringRejectsOddLength(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt();
        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        $encrypt->convertHexStringToString('68656c6c6f20776f726c642');
    }

    public function testOddLengthFileIdThrows(): void
    {
        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, 'abc', 2, ['print'], 'alpha', 'beta');
    }

    public function testGetFileIdReturnsTheHexadecimalForm(): void
    {
        $fileId = \md5('file_id');
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, $fileId, 2, ['print'], 'alpha', 'beta');
        $this->assertSame($fileId, $encrypt->getFileId());
        $this->assertSame($encrypt->getEncryptionData()['fileid'], (string) \hex2bin($encrypt->getFileId()));
    }

    public function testGetFileIdOfAGeneratedFileId(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, '', 2, ['print'], 'alpha', 'beta');
        $this->assertSame(32, \strlen($encrypt->getFileId()));
        $this->assertTrue(\ctype_xdigit($encrypt->getFileId()));
    }

    /** A generated file ID differs on every document, and so does the key. */
    public function testGeneratedFileIdIsRandom(): void
    {
        $first = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, '', 2, ['print'], 'alpha', 'beta');
        $second = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, '', 2, ['print'], 'alpha', 'beta');

        $this->assertNotSame($first->getFileId(), $second->getFileId());
        $this->assertNotSame(
            \bin2hex($first->getEncryptionData()['key']),
            \bin2hex($second->getEncryptionData()['key']),
        );
    }

    public function testConvertStringToHexString(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt();

        $result = $encrypt->convertStringToHexString('');
        $this->assertEquals('', $result);

        $result = $encrypt->convertStringToHexString('hello world');
        $this->assertEquals('68656c6c6f20776f726c64', $result);
    }

    public function testEncodeNameObject(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt();

        $result = $encrypt->encodeNameObject('');
        $this->assertEquals('', $result);

        $result = $encrypt->encodeNameObject('059akzAKZ#_=-');
        $this->assertEquals('059akzAKZ#23_=-', $result);

        $result = $encrypt->encodeNameObject('059[]{}+~*akzAKZ#_=-');
        $this->assertEquals('059#5B#5D#7B#7D#2B#7E#2AakzAKZ#23_=-', $result);
    }

    /** The NUMBER SIGN, which introduces the escape, is itself escaped as #23. */
    public function testEncodeNameObjectEscapesTheNumberSign(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt();

        $this->assertSame('#23', $encrypt->encodeNameObject('#'));
        $this->assertSame('a#23b', $encrypt->encodeNameObject('a#b'));
        // The three characters '#23' do not collapse into the one they escape.
        $this->assertSame('#2323', $encrypt->encodeNameObject('#23'));
        $this->assertNotSame($encrypt->encodeNameObject('#'), $encrypt->encodeNameObject('#23'));
    }

    public function testEscapeString(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt();

        $result = $encrypt->escapeString('');
        $this->assertEquals('', $result);

        $result = $encrypt->escapeString('hello world');
        $this->assertEquals('hello world', $result);

        $result = $encrypt->escapeString('(hello world) slash \\' . \chr(13));
        $this->assertEquals('\\(hello world\\) slash \\\\\r', $result);
    }

    public function testEncryptStringDisabled(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt();

        $result = $encrypt->encryptString('');
        $this->assertEquals('', $result);

        $result = $encrypt->encryptString('hello world');
        $this->assertEquals('hello world', $result);

        $result = $encrypt->encryptString('(hello world) slash \\' . \chr(13) . \chr(250));
        $this->assertEquals('(hello world) slash \\' . \chr(13) . \chr(250), $result);
    }

    /** Known-answer test: explicit passwords make the ciphertext reproducible. */
    public function testEncryptStringEnabled(): void
    {
        $this->bcRunIgnoringUserDeprecations(function (): void {
            $permissions = [
                'print',
                'modify',
                'copy',
                'annot-forms',
                'fill-forms',
                'extract',
                'assemble',
                'print-high',
            ];

            $enc = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 0, $permissions, 'alpha', 'beta');
            $result = $enc->encryptString('(hello world) slash \\' . \chr(13));
            $this->assertSame('eb60b1a6704029819c96d47186e45206', \md5($result));

            $enc = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 1, $permissions, 'alpha', 'beta');
            $result = $enc->encryptString('(hello world) slash \\' . \chr(13));
            $this->assertSame('5dfd302354afb05df465752ef95f7f96', \md5($result));
        });
    }

    public function testEscapeDataStringDisabled(): void
    {
        $encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt();

        $result = $encrypt->escapeDataString('');
        $this->assertEquals('()', $result);

        $result = $encrypt->escapeDataString('hello world');
        $this->assertEquals('(hello world)', $result);

        $result = $encrypt->escapeDataString('(hello world) slash \\' . \chr(13));
        $this->assertEquals('(\\(hello world\\) slash \\\\\r)', $result);
    }

    public function testEscapeDataStringEnabled(): void
    {
        $this->bcRunIgnoringUserDeprecations(function (): void {
            $permissions = [
                'print',
                'modify',
                'copy',
                'annot-forms',
                'fill-forms',
                'extract',
                'assemble',
                'print-high',
            ];

            $enc = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 0, $permissions, 'alpha', 'beta');
            $result = $enc->escapeDataString('(hello world) slash \\' . \chr(13));
            $this->assertSame('4ca79a95f6693bc06ebcc6488d6dc509', \md5($result));

            $enc = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 1, $permissions, 'alpha', 'beta');
            $result = $enc->escapeDataString('(hello world) slash \\' . \chr(13));
            $this->assertSame('f74aaf7b09d6946fc5a99ec9f0ec07e1', \md5($result));
        });
    }

    public function testGetFormattedDate(): void
    {
        $permissions = ['print', 'modify', 'copy', 'annot-forms', 'fill-forms', 'extract', 'assemble', 'print-high'];

        $enc = new \Com\Tecnick\Pdf\Encrypt\Encrypt(false);
        $result = $enc->getFormattedDate();
        $this->assertEquals('(D:', \substr($result, 0, 3));
        $this->assertEquals("+00'00')", \substr($result, -8));

        // With encryption enabled the date is encrypted, so only the
        // literal-string delimiters are predictable without the key.
        $this->bcRunIgnoringUserDeprecations(function () use ($permissions): void {
            $enc = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 0, $permissions, 'alpha', 'beta');
            $result = $enc->getFormattedDate(0, 3);
            $this->assertSame('(', \substr($result, 0, 1));
            $this->assertSame(')', \substr($result, -1));

            $dec = new \Com\Tecnick\Pdf\Encrypt\Decrypt($enc->getEncryptionData());
            $this->assertTrue($dec->authenticate('alpha'));
            $this->assertSame("D:19700101000000+00'00'", $dec->decryptString(\substr($result, 1, -1), 3));
        });
    }

    /**
     * @return array<string, array{string}>
     */
    public static function timezoneProvider(): array
    {
        return [
            'UTC' => ['UTC'],
            'ahead of UTC' => ['Europe/Rome'],
            'behind UTC' => ['America/New_York'],
            'fractional offset' => ['Asia/Kolkata'],
        ];
    }

    /** The instant is rendered in UTC, whatever the ambient timezone. */
    #[\PHPUnit\Framework\Attributes\DataProvider('timezoneProvider')]
    public function testGetFormattedDateIsTimezoneIndependent(string $timezone): void
    {
        $previous = \date_default_timezone_get();
        \date_default_timezone_set($timezone);

        try {
            $enc = new \Com\Tecnick\Pdf\Encrypt\Encrypt(false);
            $this->assertSame("(D:19700101000000+00'00')", $enc->getFormattedDate(0));
        } finally {
            \date_default_timezone_set($previous);
        }
    }

    /** The default owner password is drawn fresh for every document. */
    public function testDefaultOwnerPasswordIsRandom(): void
    {
        $first = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 2, ['print'], 'alpha');
        $second = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 2, ['print'], 'alpha');

        $firstOwner = $first->getEncryptionData()['owner_password'];
        $secondOwner = $second->getEncryptionData()['owner_password'];

        // The stored value is the padded 32-byte form of a 32 hex character string.
        $this->assertSame(32, \strlen($firstOwner));
        $this->assertTrue(\ctype_xdigit($firstOwner));
        $this->assertNotSame(\bin2hex($firstOwner), \bin2hex($secondOwner));
        // The document key derived from it differs too.
        $this->assertNotSame(
            \bin2hex($first->getEncryptionData()['key']),
            \bin2hex($second->getEncryptionData()['key']),
        );
    }

    /** An explicit owner password yields the same key on every run. */
    public function testExplicitOwnerPasswordIsDeterministic(): void
    {
        $first = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 2, ['print'], 'alpha', 'beta');
        $second = new \Com\Tecnick\Pdf\Encrypt\Encrypt(true, \md5('file_id'), 2, ['print'], 'alpha', 'beta');
        $this->assertSame(\bin2hex($first->getEncryptionData()['key']), \bin2hex($second->getEncryptionData()['key']));
    }
}
