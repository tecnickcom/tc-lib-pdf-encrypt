<?php

/**
 * DecryptTest.php
 *
 * @since     2026-04-30
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

use Com\Tecnick\Pdf\Encrypt\Decrypt;
use Com\Tecnick\Pdf\Encrypt\Encrypt;

/**
 * Decrypt Test
 *
 * @since     2026-04-30
 * @category  Library
 * @package   PdfEncrypt
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2011-2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-encrypt
 */
class DecryptTest extends TestUtil
{
    /**
     * Recipient certificate used by the public-key tests.
     *
     * Both fixtures are self-signed and hold the private key. They were made with:
     *   openssl req -x509 -nodes -days 3650 -newkey rsa:3072 -keyout cert.pem -out cert.pem
     */
    private const CERT = __DIR__ . '/data/cert.pem';

    /**
     * A second, unrelated certificate, which cert.pem cannot open.
     */
    private const CERT2 = __DIR__ . '/data/cert2.pem';

    /**
     * Construct a Decrypt from a deliberately malformed dictionary.
     *
     * The input leaves the constructor's declared shape, which is the case under test.
     *
     * @param array<string, mixed> $input Malformed encryption dictionary.
     */
    private function decryptFromMalformed(array $input): Decrypt
    {
        /** @var array{'V': int, 'mode': int, 'O': string, 'U': string, 'P': int, 'fileid': string} $dict */
        $dict = $input;
        return new Decrypt($dict);
    }

    /** Build a Decrypt object from an Encrypt instance's encryption data. */
    private function decryptFromEncrypt(Encrypt $enc): Decrypt
    {
        return new Decrypt($enc->getEncryptionData());
    }

    // -------------------------------------------------------------------------
    // decryptString round-trips
    // -------------------------------------------------------------------------

    /** RC4-40 is symmetric: the plaintext is recovered exactly, with no padding. */
    public function testDecryptStringRoundtripMode0(): void
    {
        $this->bcAssertUserDeprecationMessageMatches('/RC4 encryption.*deprecated/i', function (): void {
            $enc = new Encrypt(true, \md5('file'), 0, ['print'], 'alpha', 'beta');
            $plaintext = 'hello world';
            $ciphertext = $enc->encryptString($plaintext, 1);
            $dec = $this->decryptFromEncrypt($enc);
            $this->assertTrue($dec->authenticate('alpha'));
            $this->assertSame($plaintext, $dec->decryptString($ciphertext, 1));
        });
    }

    /** AES-128: the IV-prefixed stream decrypts to the exact plaintext. */
    public function testDecryptStringRoundtripMode2(): void
    {
        $enc = new Encrypt(true, \md5('file'), 2, ['print'], 'alpha', 'beta');
        $plaintext = 'hello world';
        $ciphertext = $enc->encryptString($plaintext, 1);
        $dec = $this->decryptFromEncrypt($enc);
        $this->assertTrue($dec->authenticate('alpha'));
        $this->assertSame($plaintext, $dec->decryptString($ciphertext, 1));
    }

    /** AES-256 R5: the full document key decrypts to the exact plaintext. */
    public function testDecryptStringRoundtripMode3(): void
    {
        $enc = new Encrypt(true, \md5('file'), 3, ['print'], 'alpha', 'beta');
        $plaintext = 'hello world';
        $ciphertext = $enc->encryptString($plaintext, 1);
        $dec = $this->decryptFromEncrypt($enc);
        $this->assertTrue($dec->authenticate('alpha'));
        $this->assertSame($plaintext, $dec->decryptString($ciphertext, 1));
    }

    /** AES-256 R6: as R5, with the Algorithm 2.B password hash. */
    public function testDecryptStringRoundtripMode4(): void
    {
        $enc = new Encrypt(true, \md5('file'), 4, ['print'], 'alpha', 'beta');
        $plaintext = 'hello world';
        $ciphertext = $enc->encryptString($plaintext, 1);
        $dec = $this->decryptFromEncrypt($enc);
        $this->assertTrue($dec->authenticate('alpha'));
        $this->assertSame($plaintext, $dec->decryptString($ciphertext, 1));
    }

    /**
     * @return array<string, array{int}>
     */
    public static function aesModeProvider(): array
    {
        return [
            'mode 2 AES-128' => [2],
            'mode 3 AES-256 R5' => [3],
            'mode 4 AES-256 R6' => [4],
        ];
    }

    /**
     * Block-aligned plaintext round-trips: PKCS#7 appends a full padding block
     * on encryption, which decryption removes.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('aesModeProvider')]
    public function testDecryptStringRoundtripBlockAligned(int $mode): void
    {
        $enc = new Encrypt(true, \md5('file'), $mode, ['print'], 'alpha', 'beta');
        $plaintext = \str_repeat('A', 16);
        $ciphertext = $enc->encryptString($plaintext, 7);
        $dec = $this->decryptFromEncrypt($enc);
        $this->assertTrue($dec->authenticate('alpha'));
        $this->assertSame($plaintext, $dec->decryptString($ciphertext, 7));
    }

    /** Empty plaintext round-trips to an empty string in all AES modes. */
    #[\PHPUnit\Framework\Attributes\DataProvider('aesModeProvider')]
    public function testDecryptStringRoundtripEmpty(int $mode): void
    {
        $enc = new Encrypt(true, \md5('file'), $mode, ['print'], 'alpha', 'beta');
        $ciphertext = $enc->encryptString('', 3);
        $dec = $this->decryptFromEncrypt($enc);
        $this->assertTrue($dec->authenticate('alpha'));
        $this->assertSame('', $dec->decryptString($ciphertext, 3));
    }

    /** decryptString() throws when called before authenticate(). */
    public function testDecryptStringWithoutAuthThrows(): void
    {
        $enc = new Encrypt(true, \md5('file'), 3, ['print'], 'userpass', 'ownerpass');
        $dec = $this->decryptFromEncrypt($enc);
        $ciphertext = $enc->encryptString('hello world', 1);

        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        $dec->decryptString($ciphertext, 1);
    }

    /** decryptString() throws after a failed authentication. */
    public function testDecryptStringAfterFailedAuthThrows(): void
    {
        $enc = new Encrypt(true, \md5('file'), 3, ['print'], 'userpass', 'ownerpass');
        $ciphertext = $enc->encryptString('hello world', 1);
        $dec = $this->decryptFromEncrypt($enc);
        $this->assertFalse($dec->authenticate('wrong'));

        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        $dec->decryptString($ciphertext, 1);
    }

    /** An AES stream carries a 16-byte IV plus at least one whole block. */
    public function testDecryptStringAesTooShortData(): void
    {
        $enc = new Encrypt(true, \md5('file'), 3, ['print'], 'alpha', 'beta');
        $dec = $this->decryptFromEncrypt($enc);
        $this->assertTrue($dec->authenticate('alpha'));

        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        $dec->decryptString(\str_repeat('x', 16), 0);
    }

    /** A ciphertext that is not block-aligned is rejected. */
    public function testDecryptStringAesUnalignedData(): void
    {
        $enc = new Encrypt(true, \md5('file'), 3, ['print'], 'alpha', 'beta');
        $dec = $this->decryptFromEncrypt($enc);
        $this->assertTrue($dec->authenticate('alpha'));

        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        $dec->decryptString(\str_repeat('x', 25), 0);
    }

    /** A tampered ciphertext never decrypts to the original plaintext. */
    public function testDecryptStringTamperedData(): void
    {
        $enc = new Encrypt(true, \md5('file'), 3, ['print'], 'alpha', 'beta');
        $plaintext = 'hello world';
        $ciphertext = $enc->encryptString($plaintext, 1);
        $dec = $this->decryptFromEncrypt($enc);
        $this->assertTrue($dec->authenticate('alpha'));

        $last = \strlen($ciphertext) - 1;
        $tampered = \substr($ciphertext, 0, $last) . \chr(\ord($ciphertext[$last]) ^ 0xFF);

        // CBC carries no integrity check: the tampered block is rejected when it
        // decrypts to an invalid PKCS#7 padding, and yields other bytes otherwise.
        $decrypted = null;

        try {
            $decrypted = $dec->decryptString($tampered, 1);
        } catch (\Com\Tecnick\Pdf\Encrypt\Exception) {
            $decrypted = null;
        }

        $this->assertNotSame($plaintext, $decrypted);
    }

    /** A stream whose PKCS#7 padding is invalid is rejected. */
    public function testDecryptStringInvalidPaddingThrows(): void
    {
        $enc = new Encrypt(true, \md5('file'), 3, ['print'], 'alpha', 'beta');
        $dec = $this->decryptFromEncrypt($enc);
        $this->assertTrue($dec->authenticate('alpha'));

        // A block of zero bytes ends in 0x00, which is not a padding length.
        $ivect = \str_repeat("\x00", 16);
        $block = \openssl_encrypt(
            $ivect,
            'aes-256-cbc',
            $dec->getDocumentKey(),
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $ivect,
        );
        $this->assertIsString($block);

        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class, 'decryption failed');
        $dec->decryptString($ivect . $block, 1);
    }

    // -------------------------------------------------------------------------
    // getDocumentKey after failed/successful authentication
    // -------------------------------------------------------------------------

    /** A key present in the input dictionary does not survive a failed authentication. */
    public function testGetDocumentKeyAfterFailedAuth(): void
    {
        $enc = new Encrypt(true, \md5('file'), 3, ['print'], 'userpass', 'ownerpass');
        $data = $enc->getEncryptionData();
        $this->assertNotSame('', $data['key']);

        $dec = new Decrypt($data);
        // The constructor clears the key; only authenticate() sets one.
        $this->assertSame('', $dec->getDocumentKey());
        $this->assertFalse($dec->authenticate('wrong'));
        $this->assertSame('', $dec->getDocumentKey());
    }

    /** getObjectKey() throws when called before authenticate(). */
    public function testGetObjectKeyWithoutAuthThrows(): void
    {
        $enc = new Encrypt(true, \md5('file'), 2, ['print'], 'userpass', 'ownerpass');
        $dec = $this->decryptFromEncrypt($enc);

        $this->bcExpectException(
            \Com\Tecnick\Pdf\Encrypt\Exception::class,
            'not authenticated: call authenticate() before deriving object keys',
        );
        $dec->getObjectKey(1);
    }

    /** After authentication it returns the same key the writer used. */
    public function testGetObjectKeyMatchesTheWriter(): void
    {
        $enc = new Encrypt(true, \md5('file'), 2, ['print'], 'userpass', 'ownerpass');
        $dec = $this->decryptFromEncrypt($enc);
        $this->assertTrue($dec->authenticate('userpass'));
        $this->assertSame(\bin2hex($enc->getObjectKey(12, 3)), \bin2hex($dec->getObjectKey(12, 3)));
    }

    /** getObjectKey() throws again after a failed authentication. */
    public function testGetObjectKeyAfterFailedAuthThrows(): void
    {
        $enc = new Encrypt(true, \md5('file'), 2, ['print'], 'userpass', 'ownerpass');
        $dec = $this->decryptFromEncrypt($enc);
        $this->assertTrue($dec->authenticate('userpass'));
        $this->assertFalse($dec->authenticate('wrong'));

        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class, 'not authenticated');
        $dec->getObjectKey(1);
    }

    // -------------------------------------------------------------------------
    // Public-key mode authentication
    // -------------------------------------------------------------------------

    public function testAuthenticatePublicKeyEmptyPathReturnsFalse(): void
    {
        $pubkeys = [['c' => self::CERT, 'p' => ['print']]];
        $enc = new Encrypt(true, \md5('file'), 3, pubkeys: $pubkeys);
        $dec = $this->decryptFromEncrypt($enc);
        $this->assertFalse($dec->authenticate('', ''));
    }

    public function testAuthenticatePublicKeyWrongKeyReturnsFalse(): void
    {
        $pubkeys = [['c' => self::CERT, 'p' => ['print']]];
        $enc = new Encrypt(true, \md5('file'), 3, pubkeys: $pubkeys);
        $dec = $this->decryptFromEncrypt($enc);
        // This file is not a PEM key, so openssl_pkcs7_decrypt() fails.
        $this->assertFalse($dec->authenticate('', __FILE__));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function malformedRecipientProvider(): array
    {
        return [
            'non-hexadecimal characters' => ['ZZZZINVALID!!'],
            'odd number of digits' => ['abc'],
            'empty entry' => [''],
        ];
    }

    /**
     * Algorithm 3 hashes the bytes of every Recipients entry, so an entry that
     * is not even-length hexadecimal is refused by the constructor.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('malformedRecipientProvider')]
    public function testMalformedHexRecipientThrows(string $recipient): void
    {
        $enc = new Encrypt(true, \md5('file'), 3, pubkeys: [['c' => self::CERT, 'p' => ['print']]]);
        $data = $enc->getEncryptionData();
        $data['Recipients'] = [$data['Recipients'][0] ?? '', $recipient];

        $this->bcExpectException(
            \Com\Tecnick\Pdf\Encrypt\Exception::class,
            'the Recipients entry at index 1 is not an even-length hexadecimal string',
        );
        new Decrypt($data);
    }

    /**
     * Values for /EncryptMetadata, with the authentication result each one
     * produces on a document written with the flag off.
     *
     * @return array<string, array{mixed, bool|string}>
     */
    public static function booleanEntryProvider(): array
    {
        return [
            'false matches the document' => [false, true],
            'the PDF keyword false matches' => ['false', true],
            'true reads a different key' => [true, false],
            'the PDF keyword true reads a different key' => ['true', false],
            'null falls back to the default, which is true' => [null, false],
            'an integer' => [0, 'reject'],
            'any other string' => ['no', 'reject'],
            'an array' => [[], 'reject'],
        ];
    }

    /**
     * A PDF boolean is accepted as a boolean or as its keyword; any other value
     * is rejected.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('booleanEntryProvider')]
    public function testEncryptMetadataEntryIsValidated(mixed $value, bool|string $authenticates): void
    {
        $enc = new Encrypt(true, \md5('file'), 2, ['print'], 'userpass', 'ownerpass', null, false);
        $data = $enc->getEncryptionData();
        $data['EncryptMetadata'] = $value;
        // The entry leaves the declared shape, which is the case under test.
        /** @var array{'V': int, 'mode': int, 'O': string, 'U': string, 'P': int, 'fileid': string} $data */

        if ($authenticates === 'reject') {
            $this->bcExpectException(
                \Com\Tecnick\Pdf\Encrypt\Exception::class,
                'the EncryptMetadata entry must be a boolean',
            );
            new Decrypt($data);
            return;
        }

        // The document was written with the flag off, so only a reading that
        // agrees with it derives the right key.
        $dec = new Decrypt($data);
        $this->assertSame($authenticates, $dec->authenticate('userpass'));
    }

    public function testPubkeyEntryIsValidated(): void
    {
        $enc = new Encrypt(true, \md5('file'), 2, ['print'], 'userpass', 'ownerpass');
        $data = $enc->getEncryptionData();
        $data['pubkey'] = 'yes';
        /** @var array{'V': int, 'mode': int, 'O': string, 'U': string, 'P': int, 'fileid': string} $data */

        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class, 'the pubkey entry must be a boolean');
        new Decrypt($data);
    }

    public function testUnsupportedSecurityHandlerIsNamed(): void
    {
        $this->bcExpectException(
            \Com\Tecnick\Pdf\Encrypt\Exception::class,
            'unsupported security handler: Vendor.Custom',
        );
        Decrypt::fromEncryptionDictionary(['Filter' => 'Vendor.Custom', 'V' => 4, 'R' => 4, 'CFM' => 'AESV2']);
    }

    /** A decryptor refuses to write an encryption dictionary. */
    public function testGetPdfEncryptionObjIsRefused(): void
    {
        $enc = new Encrypt(true, \md5('file'), 2, ['print'], 'userpass', 'ownerpass');
        $dec = new Decrypt($enc->getEncryptionData());

        $this->bcExpectException(
            \Com\Tecnick\Pdf\Encrypt\Exception::class,
            'Decrypt cannot write an encryption dictionary',
        );
        $pon = 0;
        $dec->getPdfEncryptionObj($pon);
    }

    /**
     * A recipient that does not match the certificate is skipped, and a later
     * matching one yields the document key.
     */
    public function testAuthenticationSucceedsThroughASecondRecipient(): void
    {
        $enc = new Encrypt(true, \md5('file'), 3, pubkeys: [
            ['c' => self::CERT2, 'p' => ['print']],
            ['c' => self::CERT, 'p' => ['copy']],
        ]);
        $data = $enc->getEncryptionData();
        $this->assertCount(2, $data['Recipients']);

        $dec = new Decrypt($data);
        $this->assertTrue($dec->authenticate('', self::CERT));
        $this->assertSame(\bin2hex($data['key']), \bin2hex($dec->getDocumentKey()));
        $this->assertSame($enc->getUserPermissionCode(['copy'], 3), $dec->getRecipientPermissions());
    }

    // -------------------------------------------------------------------------
    // AESnopad::decrypt() direct tests
    // -------------------------------------------------------------------------

    public function testAesnopadDecryptRoundtrip32Bytes(): void
    {
        $aesnopad = new \Com\Tecnick\Pdf\Encrypt\Type\AESnopad();
        $key = \str_repeat('k', 32);
        $plaintext = \str_repeat('p', 32); // the length of a file key
        $ciphertext = $aesnopad->encrypt($plaintext, $key);
        $decrypted = $aesnopad->decrypt($ciphertext, $key);
        $this->assertSame($plaintext, $decrypted);
    }

    public function testAesnopadDecryptRoundtripAes128(): void
    {
        $aesnopad = new \Com\Tecnick\Pdf\Encrypt\Type\AESnopad();
        $key = \str_repeat('k', 16);
        $plaintext = \str_repeat('p', 16);
        $ivect = \Com\Tecnick\Pdf\Encrypt\Type\AESnopad::IVECT;
        $ciphertext = $aesnopad->encrypt($plaintext, $key, $ivect, 'aes-128-cbc');
        $decrypted = $aesnopad->decrypt($ciphertext, $key, $ivect, 'aes-128-cbc');
        $this->assertSame($plaintext, $decrypted);
    }

    public function testAesnopadDecryptInvalidCipherThrows(): void
    {
        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        $aesnopad = new \Com\Tecnick\Pdf\Encrypt\Type\AESnopad();
        $aesnopad->decrypt('data', \str_repeat('k', 32), \Com\Tecnick\Pdf\Encrypt\Type\AESnopad::IVECT, 'des-cbc');
    }

    // -------------------------------------------------------------------------
    // Recovered key against the generated key
    // -------------------------------------------------------------------------

    /**
     * @return array<string, array{int}>
     */
    public static function allModesProvider(): array
    {
        return [
            'mode 0 RC4-40' => [0],
            'mode 1 RC4-128' => [1],
            'mode 2 AES-128' => [2],
            'mode 3 AES-256 R5' => [3],
            'mode 4 AES-256 R6' => [4],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('allModesProvider')]
    public function testRecoveredKeyMatchesGeneratedKey(int $mode): void
    {
        $this->bcRunIgnoringUserDeprecations(function () use ($mode): void {
            $enc = new Encrypt(true, \md5('file'), $mode, ['print'], 'userpass', 'ownerpass');
            $expected = $enc->getEncryptionData()['key'];

            foreach (['userpass' => 'user', 'ownerpass' => 'owner'] as $password => $role) {
                $dec = $this->decryptFromEncrypt($enc);
                $this->assertTrue($dec->authenticate($password), $role);
                $this->assertSame(\bin2hex($expected), \bin2hex($dec->getDocumentKey()), $role);
                $this->assertSame($role, $dec->getAuthenticatedRole());
            }
        });
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('allModesProvider')]
    public function testWrongPasswordLeavesNoKey(int $mode): void
    {
        $this->bcRunIgnoringUserDeprecations(function () use ($mode): void {
            $enc = new Encrypt(true, \md5('file'), $mode, ['print'], 'userpass', 'ownerpass');
            $dec = $this->decryptFromEncrypt($enc);
            $this->assertFalse($dec->authenticate('wrongpassword'));
            $this->assertSame('', $dec->getDocumentKey());
            $this->assertNull($dec->getAuthenticatedRole());
        });
    }

    /** RC4-128 round-trips to the exact plaintext. */
    public function testDecryptStringRoundtripMode1(): void
    {
        $this->bcRunIgnoringUserDeprecations(function (): void {
            $enc = new Encrypt(true, \md5('file'), 1, ['print'], 'alpha', 'beta');
            $plaintext = 'hello world';
            $ciphertext = $enc->encryptString($plaintext, 1);
            $dec = $this->decryptFromEncrypt($enc);
            $this->assertTrue($dec->authenticate('alpha'));
            $this->assertSame($plaintext, $dec->decryptString($ciphertext, 1));
        });
    }

    /** Payloads spanning many blocks round-trip byte for byte. */
    #[\PHPUnit\Framework\Attributes\DataProvider('allModesProvider')]
    public function testDecryptStringRoundtripMultiBlock(int $mode): void
    {
        $this->bcRunIgnoringUserDeprecations(function () use ($mode): void {
            $enc = new Encrypt(true, \md5('file'), $mode, ['print'], 'alpha', 'beta');
            $dec = $this->decryptFromEncrypt($enc);
            $this->assertTrue($dec->authenticate('alpha'));

            // 8192 is the RC4 keystream chunk size; the lengths around it cover
            // the flush boundary.
            foreach ([1, 15, 16, 17, 255, 4096, 8191, 8192, 8193, 20000] as $len) {
                $plaintext = \random_bytes($len);
                $ciphertext = $enc->encryptString($plaintext, 11);
                $this->assertSame(
                    \bin2hex($plaintext),
                    \bin2hex($dec->decryptString($ciphertext, 11)),
                    'mode ' . $mode . ' length ' . $len,
                );
            }
        });
    }

    // -------------------------------------------------------------------------
    // Password length boundaries (R5 / R6)
    // -------------------------------------------------------------------------

    /**
     * R5 and R6 hash at most 127 bytes of the password.
     *
     * @return array<string, array{int, int<0, max>}>
     */
    public static function passwordLengthProvider(): array
    {
        return [
            'mode 3, 126 bytes' => [3, 126],
            'mode 3, 127 bytes' => [3, 127],
            'mode 3, 128 bytes' => [3, 128],
            'mode 3, 200 bytes' => [3, 200],
            'mode 4, 126 bytes' => [4, 126],
            'mode 4, 127 bytes' => [4, 127],
            'mode 4, 128 bytes' => [4, 128],
            'mode 4, 200 bytes' => [4, 200],
        ];
    }

    /**
     * @param int<0, max> $length
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('passwordLengthProvider')]
    public function testLongPasswordAuthenticates(int $mode, int $length): void
    {
        $password = \str_repeat('A', $length);
        $enc = new Encrypt(true, \md5('file'), $mode, ['print'], $password, 'ownerpass');
        $dec = $this->decryptFromEncrypt($enc);
        $this->assertTrue($dec->authenticate($password));
        $this->assertSame(32, \strlen($dec->getDocumentKey()));
    }

    // -------------------------------------------------------------------------
    // Malformed encryption dictionaries
    // -------------------------------------------------------------------------

    /**
     * Each case overrides exactly one field of an otherwise valid mode 4
     * dictionary, and names the message that reports it.
     *
     * @return array<string, array{int, int, int<0, max>, int<0, max>, int<0, max>, int<0, max>, int<0, max>, string}>
     */
    public static function malformedInputProvider(): array
    {
        //  mode, Length, O, U, OE, UE, Perms lengths, expected message
        return [
            'mode too low' => [-1, 256, 48, 48, 32, 32, 16, 'unknown encryption mode: -1'],
            'mode too high' => [5, 256, 48, 48, 32, 32, 16, 'unknown encryption mode: 5'],
            'zero length' => [4, 0, 48, 48, 32, 32, 16, 'invalid key length: 0'],
            'length not a multiple of 8' => [4, 37, 48, 48, 32, 32, 16, 'invalid key length: 37'],
            'length too large' => [4, 512, 48, 48, 32, 32, 16, 'invalid key length: 512'],
            'AES-256 with 128 bit length' => [
                4,
                128,
                48,
                48,
                32,
                32,
                16,
                'mode 4 requires a key length between 256 and 256 bits, got 128',
            ],
            'short O' => [4, 256, 32, 48, 32, 32, 16, 'the O entry must be at least 48 bytes'],
            'short U' => [4, 256, 48, 40, 32, 32, 16, 'the U entry must be at least 48 bytes'],
            'short OE' => [4, 256, 48, 48, 16, 32, 16, 'the OE entry must be 32 bytes'],
            'short UE' => [4, 256, 48, 48, 32, 16, 16, 'the UE entry must be 32 bytes'],
            'short Perms' => [4, 256, 48, 48, 32, 32, 8, 'the Perms entry must be 16 bytes'],
        ];
    }

    /**
     * @param int<0, max> $olen
     * @param int<0, max> $ulen
     * @param int<0, max> $oelen
     * @param int<0, max> $uelen
     * @param int<0, max> $permslen
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('malformedInputProvider')]
    public function testMalformedInputThrows(
        int $mode,
        int $length,
        int $olen,
        int $ulen,
        int $oelen,
        int $uelen,
        int $permslen,
        string $message,
    ): void {
        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class, $message);
        new Decrypt([
            'V' => 5,
            'Length' => $length,
            'P' => -4,
            'mode' => $mode,
            'fileid' => '',
            'O' => \str_repeat('o', $olen),
            'U' => \str_repeat('u', $ulen),
            'OE' => \str_repeat('e', $oelen),
            'UE' => \str_repeat('e', $uelen),
            'perms' => \str_repeat('p', $permslen),
        ]);
    }

    /** The same dictionary with every field correct constructs. */
    public function testWellFormedInputIsAccepted(): void
    {
        $dec = new Decrypt([
            'V' => 5,
            'Length' => 256,
            'P' => -4,
            'mode' => 4,
            'fileid' => '',
            'O' => \str_repeat('o', 48),
            'U' => \str_repeat('u', 48),
            'OE' => \str_repeat('e', 32),
            'UE' => \str_repeat('e', 32),
            'perms' => \str_repeat('p', 16),
        ]);
        $this->assertFalse($dec->authenticate('userpass'));
    }

    /**
     * A mode paired with a V or a key length it cannot have is rejected.
     *
     * @return array<string, array{int, int, int, string}>
     */
    public static function incoherentModeProvider(): array
    {
        //  mode, V, Length, expected message
        return [
            'RC4-40 with V 2' => [0, 2, 40, 'mode 0 requires V 1, got 2'],
            'RC4-128 with V 5' => [1, 5, 128, 'mode 1 requires V 2 or 4, got 5'],
            'AES-128 with V 2' => [2, 2, 128, 'mode 2 requires V 4, got 2'],
            'AES-256 with V 4' => [3, 4, 256, 'mode 3 requires V 5, got 4'],
            'RC4-40 with a 128 bit key' => [0, 1, 128, 'mode 0 requires a key length between 40 and 40 bits, got 128'],
            'AES-128 with a 40 bit key' => [2, 4, 40, 'mode 2 requires a key length between 128 and 128 bits, got 40'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('incoherentModeProvider')]
    public function testIncoherentModeAndVersionThrow(int $mode, int $version, int $length, string $message): void
    {
        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class, $message);
        new Decrypt([
            'V' => $version,
            'Length' => $length,
            'P' => -4,
            'mode' => $mode,
            'fileid' => \md5('file', true),
            'O' => \str_repeat('o', 48),
            'U' => \str_repeat('u', 48),
            'OE' => \str_repeat('e', 32),
            'UE' => \str_repeat('e', 32),
            'perms' => \str_repeat('p', 16),
        ]);
    }

    /** An empty UE entry is rejected by the constructor. */
    public function testEmptyWrappedKeyIsRejected(): void
    {
        $enc = new Encrypt(true, \md5('file'), 4, ['print'], 'userpass', 'ownerpass');
        $data = $enc->getEncryptionData();
        $data['UE'] = '';

        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class, 'the UE entry must be 32 bytes');
        new Decrypt($data);
    }

    // -------------------------------------------------------------------------
    // Perms validation on self-produced documents
    // -------------------------------------------------------------------------

    /** A Perms block that does not decrypt to the 'adb' marker is rejected. */
    public function testCorruptedPermsBlockIsRejected(): void
    {
        $enc = new Encrypt(true, \md5('file'), 4, ['print'], 'userpass', 'ownerpass');
        $data = $enc->getEncryptionData();
        $data['perms'] = \str_repeat("\x00", 16);

        $dec = new Decrypt($data);
        $this->assertFalse($dec->authenticate('userpass'));
        $this->assertSame('', $dec->getDocumentKey());
    }

    /**
     * @return array<string, array{int}>
     */
    public static function aes256ModeProvider(): array
    {
        return [
            'mode 3 AES-256 R5' => [3],
            'mode 4 AES-256 R6' => [4],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('aes256ModeProvider')]
    public function testTamperedPermissionsAreRejected(int $mode): void
    {
        $enc = new Encrypt(true, \md5('file'), $mode, ['print'], 'userpass', 'ownerpass');
        $data = $enc->getEncryptionData();
        $data['P'] = -1; // grant everything

        $dec = new Decrypt($data);
        $this->assertFalse($dec->authenticate('userpass'));
        $this->assertSame('', $dec->getDocumentKey());
    }

    // -------------------------------------------------------------------------
    // Public-key mode
    // -------------------------------------------------------------------------

    /**
     * @return array<string, array{int}>
     */
    public static function pubkeyModeProvider(): array
    {
        return [
            'mode 1' => [1],
            'mode 2' => [2],
            'mode 3' => [3],
            'mode 4' => [4],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('pubkeyModeProvider')]
    public function testPublicKeyRecoversTheGeneratedKey(int $mode): void
    {
        $this->bcRunIgnoringUserDeprecations(function () use ($mode): void {
            $pubkeys = [['c' => self::CERT, 'p' => ['print']]];
            $enc = new Encrypt(true, \md5('file'), $mode, pubkeys: $pubkeys);
            $expected = $enc->getEncryptionData()['key'];

            $dec = $this->decryptFromEncrypt($enc);
            $this->assertTrue($dec->authenticate('', self::CERT));
            $this->assertSame(\bin2hex($expected), \bin2hex($dec->getDocumentKey()));
        });
    }

    /** Public-key key derivation honours the EncryptMetadata flag. */
    public function testPublicKeyWithoutMetadataEncryption(): void
    {
        $pubkeys = [['c' => self::CERT, 'p' => ['print']]];
        $enc = new Encrypt(true, \md5('file'), 3, pubkeys: $pubkeys, encryptMetadata: false);
        $expected = $enc->getEncryptionData()['key'];

        $dec = $this->decryptFromEncrypt($enc);
        $this->assertTrue($dec->authenticate('', self::CERT));
        $this->assertSame(\bin2hex($expected), \bin2hex($dec->getDocumentKey()));
    }

    /** The matching recipient may appear anywhere in the Recipients array. */
    public function testPublicKeyMultipleRecipients(): void
    {
        $enc = new Encrypt(true, \md5('file'), 3, pubkeys: [
            ['c' => self::CERT, 'p' => ['print']],
            ['c' => self::CERT2, 'p' => ['copy']],
        ]);
        $data = $enc->getEncryptionData();
        $this->assertCount(2, $data['Recipients']);

        foreach ([self::CERT, self::CERT2] as $certPath) {
            $dec = new Decrypt($data);
            $this->assertTrue($dec->authenticate('', $certPath));
            $this->assertSame(\bin2hex($data['key']), \bin2hex($dec->getDocumentKey()));
        }
    }

    /** A recipient list with no usable entry does not authenticate. */
    public function testPublicKeyNoMatchingRecipient(): void
    {
        // The document is written for the second certificate only.
        $enc = new Encrypt(true, \md5('file'), 3, pubkeys: [['c' => self::CERT2, 'p' => ['print']]]);
        $dec = $this->decryptFromEncrypt($enc);
        $this->assertFalse($dec->authenticate('', self::CERT));
        $this->assertNull($dec->getAuthenticatedRole());
        $this->assertSame('', $dec->getDocumentKey());
    }

    public function testPublicKeyMissingFileReturnsFalse(): void
    {
        $enc = new Encrypt(true, \md5('file'), 3, pubkeys: [['c' => self::CERT, 'p' => ['print']]]);
        $dec = $this->decryptFromEncrypt($enc);
        $this->assertFalse($dec->authenticate('', __DIR__ . '/data/does-not-exist.pem'));
    }

    /**
     * A public-key document has no /P entry: the permissions are read back from
     * the matching recipient envelope.
     */
    public function testPublicKeyRecipientPermissionsAreRecovered(): void
    {
        $enc = new Encrypt(true, \md5('file'), 3, pubkeys: [['c' => self::CERT, 'p' => ['print', 'modify']]]);
        $expected = $enc->getUserPermissionCode(['print', 'modify'], 3);

        $dec = $this->decryptFromEncrypt($enc);
        $this->assertTrue($dec->authenticate('', self::CERT));
        $this->assertSame('recipient', $dec->getAuthenticatedRole());
        $this->assertSame($expected, $dec->getRecipientPermissions());
    }

    /**
     * The permissions belong to the matching recipient, not to the first one:
     * each entry is written for a different certificate.
     */
    public function testPublicKeyRecipientPermissionsComeFromTheMatchingEntry(): void
    {
        $enc = new Encrypt(true, \md5('file'), 3, pubkeys: [
            ['c' => self::CERT2, 'p' => ['print']],
            ['c' => self::CERT, 'p' => ['copy']],
        ]);
        $dec = $this->decryptFromEncrypt($enc);
        $this->assertTrue($dec->authenticate('', self::CERT));
        $this->assertSame($enc->getUserPermissionCode(['copy'], 3), $dec->getRecipientPermissions());
        $this->assertNotSame($enc->getUserPermissionCode(['print'], 3), $dec->getRecipientPermissions());
    }

    /** A recipient without a 'p' entry is granted every permission. */
    public function testPublicKeyRecipientWithoutPermissions(): void
    {
        $enc = new Encrypt(true, \md5('file'), 3, pubkeys: [['c' => self::CERT]]);
        $dec = $this->decryptFromEncrypt($enc);
        $this->assertTrue($dec->authenticate('', self::CERT));
        $this->assertSame($enc->getUserPermissionCode([], 3), $dec->getRecipientPermissions());
    }

    public function testRecipientPermissionsAreNullOutsidePublicKeyMode(): void
    {
        $enc = new Encrypt(true, \md5('file'), 4, ['print'], 'userpass', 'ownerpass');
        $dec = $this->decryptFromEncrypt($enc);
        $this->assertTrue($dec->authenticate('userpass'));
        $this->assertNull($dec->getRecipientPermissions());
    }

    public function testRecipientPermissionsAreClearedByAFailedAuthentication(): void
    {
        $enc = new Encrypt(true, \md5('file'), 3, pubkeys: [['c' => self::CERT, 'p' => ['print']]]);
        $dec = $this->decryptFromEncrypt($enc);
        $this->assertTrue($dec->authenticate('', self::CERT));
        $this->assertNotNull($dec->getRecipientPermissions());

        $this->assertFalse($dec->authenticate('', __FILE__));
        $this->assertNull($dec->getRecipientPermissions());
        $this->assertNull($dec->getAuthenticatedRole());
    }

    // -------------------------------------------------------------------------
    // Missing dictionary entries
    // -------------------------------------------------------------------------

    /**
     * @return array<string, array{string}>
     */
    public static function requiredFieldProvider(): array
    {
        return [
            'V' => ['V'],
            'O' => ['O'],
            'U' => ['U'],
            'P' => ['P'],
            'fileid' => ['fileid'],
            'mode' => ['mode'],
        ];
    }

    /**
     * A missing required entry raises the library exception and no PHP
     * diagnostic.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('requiredFieldProvider')]
    public function testMissingRequiredEntryThrows(string $field): void
    {
        $enc = new Encrypt(true, \md5('file'), 2, ['print'], 'userpass', 'ownerpass');
        $data = $enc->getEncryptionData();
        unset($data[$field]);

        $raised = [];
        \set_error_handler(static function (int $errno, string $errstr) use (&$raised): bool {
            $raised[] = $errno . ': ' . $errstr;
            return true;
        });

        try {
            $this->decryptFromMalformed($data);
            $this->fail('missing ' . $field . ' did not throw');
        } catch (\Com\Tecnick\Pdf\Encrypt\Exception $exception) {
            $this->assertStringContainsString($field, $exception->getMessage());
        } finally {
            \restore_error_handler();
        }

        $this->assertSame([], $raised, 'missing ' . $field . ' raised a PHP diagnostic');
    }

    /**
     * @return array<string, array{string, mixed}>
     */
    public static function wrongTypeProvider(): array
    {
        return [
            'V as an object' => ['V', new \stdClass()],
            'mode as an array' => ['mode', []],
            'O as an integer' => ['O', 7],
            'U as null' => ['U', null],
            'P as a non-numeric string' => ['P', 'many'],
            'Length as a float string' => ['Length', '12.5'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('wrongTypeProvider')]
    public function testWrongTypeEntryThrows(string $field, mixed $value): void
    {
        $enc = new Encrypt(true, \md5('file'), 2, ['print'], 'userpass', 'ownerpass');
        $data = $enc->getEncryptionData();
        $data[$field] = $value;

        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        $this->decryptFromMalformed($data);
    }

    /** Integer entries are accepted as numeric strings, as a parser reports them. */
    public function testNumericStringEntriesAreAccepted(): void
    {
        $enc = new Encrypt(true, \md5('file'), 2, ['print'], 'userpass', 'ownerpass');
        $data = $enc->getEncryptionData();
        $data['V'] = (string) $data['V'];
        $data['P'] = (string) $data['P'];
        $data['Length'] = (string) $data['Length'];

        $dec = $this->decryptFromMalformed($data);
        $this->assertTrue($dec->authenticate('userpass'));
    }

    public function testNonStringRecipientEntryThrows(): void
    {
        $enc = new Encrypt(true, \md5('file'), 3, pubkeys: [['c' => self::CERT, 'p' => ['print']]]);
        $data = $enc->getEncryptionData();
        $data['Recipients'] = [42];

        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class, 'every Recipients entry must be a string');
        $this->decryptFromMalformed($data);
    }

    /** Public-key mode requires a non-empty Recipients array. */
    public function testEmptyRecipientListThrows(): void
    {
        $enc = new Encrypt(true, \md5('file'), 3, pubkeys: [['c' => self::CERT, 'p' => ['print']]]);
        $data = $enc->getEncryptionData();
        $data['Recipients'] = [];

        $this->bcExpectException(
            \Com\Tecnick\Pdf\Encrypt\Exception::class,
            'public-key mode requires a non-empty Recipients array',
        );
        new Decrypt($data);
    }

    /** Revisions 2 to 4 derive the key from the file ID, so an empty one is refused. */
    public function testEmptyFileIdThrowsBelowRevisionFive(): void
    {
        $enc = new Encrypt(true, \md5('file'), 2, ['print'], 'userpass', 'ownerpass');
        $data = $enc->getEncryptionData();
        $data['fileid'] = '';

        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        new Decrypt($data);
    }

    // -------------------------------------------------------------------------
    // Implicit key length and the dictionary factory
    // -------------------------------------------------------------------------

    /**
     * @return array<string, array{int, int}>
     */
    public static function implicitLengthProvider(): array
    {
        //  library mode, expected key length in bytes
        return [
            'mode 2 (V 4)' => [2, 16],
            'mode 3 (V 5)' => [3, 32],
            'mode 4 (V 5)' => [4, 32],
        ];
    }

    /** /Length is redundant for V 4 and V 5, and a producer may omit it. */
    #[\PHPUnit\Framework\Attributes\DataProvider('implicitLengthProvider')]
    public function testKeyLengthIsInferredWhenAbsent(int $mode, int $expectedKeyBytes): void
    {
        $enc = new Encrypt(true, \md5('file'), $mode, ['print'], 'userpass', 'ownerpass');
        $data = $enc->getEncryptionData();
        unset($data['Length']);

        $dec = new Decrypt($data);
        $this->assertTrue($dec->authenticate('userpass'));
        $this->assertSame($expectedKeyBytes, \strlen($dec->getDocumentKey()));
        $this->assertSame(\bin2hex($enc->getEncryptionData()['key']), \bin2hex($dec->getDocumentKey()));
    }

    /**
     * The revision is resolved from the mode and V when the dictionary does not
     * carry /R.
     *
     * @return array<string, array{int, int, int}>
     */
    public static function resolvedRevisionProvider(): array
    {
        //  library mode, V, expected R
        return [
            'mode 0' => [0, 1, 2],
            'mode 1 as V 2' => [1, 2, 3],
            'mode 1 as V 4' => [1, 4, 4],
            'mode 2' => [2, 4, 4],
            'mode 3' => [3, 5, 5],
            'mode 4' => [4, 5, 6],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('resolvedRevisionProvider')]
    public function testRevisionIsResolvedFromTheMode(int $mode, int $version, int $revision): void
    {
        $enc = $this->bcRunIgnoringUserNotices(
            static fn(): Encrypt => new Encrypt(true, \md5('file'), $mode, ['print'], 'userpass', 'ownerpass'),
        );
        $data = $enc->getEncryptionData();
        $data['V'] = $version;
        unset($data['R']);

        $dec = new Decrypt($data);
        $this->assertSame($revision, $dec->getRevision());
    }

    /**
     * With unencrypted metadata the key derivation appends four bytes for R 4
     * and above, on both the writing and the reading side.
     */
    public function testUnencryptedMetadataKeyIsRecovered(): void
    {
        $enc = new Encrypt(true, \md5('file'), 2, ['print'], 'userpass', 'ownerpass', null, false);
        $data = $enc->getEncryptionData();
        $this->assertFalse($data['EncryptMetadata']);

        $dec = new Decrypt($data);
        $this->assertTrue($dec->authenticate('userpass'));
        $this->assertSame(\bin2hex($data['key']), \bin2hex($dec->getDocumentKey()));
    }

    /** Below V 4 the default is 40 bits, so a 128 bit document needs /Length. */
    public function testKeyLengthIsNotInferredBelowVersionFour(): void
    {
        $enc = $this->bcRunIgnoringUserNotices(
            static fn(): Encrypt => new Encrypt(true, \md5('file'), 1, ['print'], 'userpass', 'ownerpass'),
        );
        $data = $enc->getEncryptionData();
        unset($data['Length']);

        $dec = new Decrypt($data);
        $this->assertFalse($dec->authenticate('userpass'));
    }

    /**
     * @return array<string, array{int, int, string, int}>
     */
    public static function revisionProvider(): array
    {
        //  library mode, V, CFM, R
        return [
            'R2 RC4-40' => [0, 1, '', 2],
            'R3 RC4-128' => [1, 2, '', 3],
            'R4 RC4-128' => [1, 4, 'V2', 4],
            'R4 AES-128' => [2, 4, 'AESV2', 4],
            'R5 AES-256' => [3, 5, 'AESV3', 5],
            'R6 AES-256' => [4, 5, 'AESV3', 6],
        ];
    }

    /** The mode is derived from /V, /R and /CFM. */
    #[\PHPUnit\Framework\Attributes\DataProvider('revisionProvider')]
    public function testFromEncryptionDictionaryDerivesTheMode(int $mode, int $version, string $cfm, int $rev): void
    {
        $enc = $this->bcRunIgnoringUserNotices(
            static fn(): Encrypt => new Encrypt(true, \md5('file'), $mode, ['print'], 'userpass', 'ownerpass'),
        );
        $data = $enc->getEncryptionData();

        $dict = [
            'V' => $version,
            'R' => $rev,
            'CFM' => $cfm,
            // Below V 4 the default is 40 bits, so /Length is meaningful.
            'Length' => $data['Length'],
            'O' => $data['O'],
            'U' => $data['U'],
            'P' => $data['P'],
            'fileid' => $data['fileid'],
            'OE' => $data['OE'],
            'UE' => $data['UE'],
            'Perms' => $data['perms'],
        ];

        $dec = Decrypt::fromEncryptionDictionary($dict);
        $this->assertTrue($dec->authenticate('userpass'), 'R' . $rev);
        $this->assertSame(\bin2hex($data['key']), \bin2hex($dec->getDocumentKey()));
    }

    public function testFromEncryptionDictionaryRejectsAnUnknownRevision(): void
    {
        $this->bcExpectException(
            \Com\Tecnick\Pdf\Encrypt\Exception::class,
            'unsupported encryption revision 9 with crypt filter method ""',
        );
        Decrypt::fromEncryptionDictionary(['V' => 5, 'R' => 9]);
    }

    public function testFromEncryptionDictionaryRequiresTheRevision(): void
    {
        $this->bcExpectException(
            \Com\Tecnick\Pdf\Encrypt\Exception::class,
            'the R entry is required and must be an integer',
        );
        Decrypt::fromEncryptionDictionary(['V' => 5]);
    }

    /**
     * A public-key dictionary carries no /R: the handler is recognised from
     * /Filter and the mode from /V and /CFM.
     *
     * @return array<string, array{int, string, int}>
     */
    public static function pubkeyDictionaryProvider(): array
    {
        //  library mode, CFM, V
        return [
            'V 2 RC4-128' => [1, '', 2],
            'V 4 AES-128' => [2, 'AESV2', 4],
            'V 5 AES-256' => [4, 'AESV3', 5],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('pubkeyDictionaryProvider')]
    public function testFromEncryptionDictionaryOpensAPublicKeyDocument(int $mode, string $cfm, int $version): void
    {
        $enc = $this->bcRunIgnoringUserNotices(static fn(): Encrypt => new Encrypt(true, \md5('file'), $mode, pubkeys: [
            ['c' => self::CERT, 'p' => ['print']],
        ]));
        $data = $enc->getEncryptionData();

        $dec = Decrypt::fromEncryptionDictionary([
            'Filter' => 'Adobe.PubSec',
            'SubFilter' => $data['SubFilter'],
            'V' => $version,
            'Length' => $data['Length'],
            'CFM' => $cfm,
            'Recipients' => $data['Recipients'],
        ]);
        $this->assertTrue($dec->authenticate('', self::CERT));
        $this->assertSame(\bin2hex($data['key']), \bin2hex($dec->getDocumentKey()));
    }

    /** Without /Filter, the presence of /Recipients names the handler. */
    public function testFromEncryptionDictionaryInfersPublicKeyFromRecipients(): void
    {
        $enc = new Encrypt(true, \md5('file'), 3, pubkeys: [['c' => self::CERT, 'p' => ['print']]]);
        $data = $enc->getEncryptionData();

        $dec = Decrypt::fromEncryptionDictionary([
            'V' => 5,
            'CFM' => 'AESV3',
            'Recipients' => $data['Recipients'],
        ]);
        $this->assertTrue($dec->authenticate('', self::CERT));
        $this->assertSame(\bin2hex($data['key']), \bin2hex($dec->getDocumentKey()));
    }

    public function testFromEncryptionDictionaryRejectsAnUnknownPublicKeyVersion(): void
    {
        $this->bcExpectException(
            \Com\Tecnick\Pdf\Encrypt\Exception::class,
            'unsupported public-key encryption version 3 with crypt filter method ""',
        );
        Decrypt::fromEncryptionDictionary(['Filter' => 'Adobe.PubSec', 'V' => 3, 'Recipients' => []]);
    }

    // -------------------------------------------------------------------------
    // Object generation numbers
    // -------------------------------------------------------------------------

    /**
     * @return array<string, array{int}>
     */
    public static function perObjectModeProvider(): array
    {
        return [
            'mode 0' => [0],
            'mode 1' => [1],
            'mode 2' => [2],
        ];
    }

    /** An object with a generation number above 0 round-trips. */
    #[\PHPUnit\Framework\Attributes\DataProvider('perObjectModeProvider')]
    public function testGenerationNumberRoundTrip(int $mode): void
    {
        $enc = $this->bcRunIgnoringUserNotices(
            static fn(): Encrypt => new Encrypt(true, \md5('file'), $mode, ['print'], 'userpass', 'ownerpass'),
        );
        $cipher = $enc->encryptString('generation test', 12, 3);

        $dec = $this->decryptFromEncrypt($enc);
        $this->assertTrue($dec->authenticate('userpass'));
        $this->assertSame('generation test', $dec->decryptString($cipher, 12, 3));
    }

    /** The generation number is part of the key, so the wrong one does not decrypt. */
    public function testWrongGenerationNumberDoesNotDecrypt(): void
    {
        $enc = new Encrypt(true, \md5('file'), 2, ['print'], 'userpass', 'ownerpass');
        $plaintext = 'generation test';
        $cipher = $enc->encryptString($plaintext, 12, 3);

        $dec = $this->decryptFromEncrypt($enc);
        $this->assertTrue($dec->authenticate('userpass'));

        // The wrong object key gives an invalid PKCS#7 padding, or other bytes.
        $decrypted = null;

        try {
            $decrypted = $dec->decryptString($cipher, 12, 0);
        } catch (\Com\Tecnick\Pdf\Encrypt\Exception) {
            $decrypted = null;
        }

        $this->assertNotSame($plaintext, $decrypted);
    }

    /**
     * @return array<string, array{int, int}>
     */
    public static function outOfRangeObjectProvider(): array
    {
        return [
            'negative object' => [-1, 0],
            'object above 2^24' => [0x100_0000, 0],
            'negative generation' => [1, -1],
            'generation above 2^16' => [1, 0x1_0000],
        ];
    }

    /** Algorithm 1 keeps three object bytes and two generation bytes, no more. */
    #[\PHPUnit\Framework\Attributes\DataProvider('outOfRangeObjectProvider')]
    public function testOutOfRangeObjectNumbersThrow(int $objnum, int $gennum): void
    {
        $enc = new Encrypt(true, \md5('file'), 2, ['print'], 'userpass', 'ownerpass');
        $this->bcExpectException(\Com\Tecnick\Pdf\Encrypt\Exception::class);
        $enc->getObjectKey($objnum, $gennum);
    }

    // -------------------------------------------------------------------------
    // Role resolution and the Perms metadata flag
    // -------------------------------------------------------------------------

    /**
     * @return array<string, array{int}>
     */
    public static function allPasswordModeProvider(): array
    {
        return [
            'mode 0' => [0],
            'mode 1' => [1],
            'mode 2' => [2],
            'mode 3' => [3],
            'mode 4' => [4],
        ];
    }

    /** One string used for both passwords authenticates as the owner. */
    #[\PHPUnit\Framework\Attributes\DataProvider('allPasswordModeProvider')]
    public function testIdenticalPasswordsAuthenticateAsOwner(int $mode): void
    {
        $enc = $this->bcRunIgnoringUserNotices(
            static fn(): Encrypt => new Encrypt(true, \md5('file'), $mode, ['print'], 'samepass', 'samepass'),
        );
        $dec = $this->decryptFromEncrypt($enc);
        $this->assertTrue($dec->authenticate('samepass'));
        $this->assertSame('owner', $dec->getAuthenticatedRole());
    }

    /** Distinct passwords resolve to the role that matched. */
    #[\PHPUnit\Framework\Attributes\DataProvider('allPasswordModeProvider')]
    public function testDistinctPasswordsResolveTheirOwnRole(int $mode): void
    {
        $enc = $this->bcRunIgnoringUserNotices(
            static fn(): Encrypt => new Encrypt(true, \md5('file'), $mode, ['print'], 'userpass', 'ownerpass'),
        );

        $user = $this->decryptFromEncrypt($enc);
        $this->assertTrue($user->authenticate('userpass'));
        $this->assertSame('user', $user->getAuthenticatedRole());

        $owner = $this->decryptFromEncrypt($enc);
        $this->assertTrue($owner->authenticate('ownerpass'));
        $this->assertSame('owner', $owner->getAuthenticatedRole());
    }

    /** Byte 8 of the Perms block is either 'T' or 'F'; any other value is rejected. */
    public function testPermsWithAnInvalidMetadataFlagIsRejected(): void
    {
        $enc = new Encrypt(true, \md5('file'), 4, ['print'], 'userpass', 'ownerpass', null, false);
        $data = $enc->getEncryptionData();

        $aes = new \Com\Tecnick\Pdf\Encrypt\Type\AESnopad();
        $plain = $aes->decrypt($data['perms'], $data['key']);
        $this->assertSame('F', $plain[8]);
        $plain[8] = 'X';
        $data['perms'] = $aes->encrypt($plain, $data['key']);

        $dec = new Decrypt($data);
        $this->assertFalse($dec->authenticate('userpass'));
        $this->assertSame('', $dec->getDocumentKey());
    }
}
