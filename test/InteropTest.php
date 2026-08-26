<?php

/**
 * InteropTest.php
 *
 * @since     2026-08-26
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
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Interoperability Test
 *
 * Checks the encryption dictionaries this library reads and writes against
 * fixtures produced by qpdf and against vectors computed from the specification.
 *
 * Every qpdf fixture below was produced with:
 *   qpdf --allow-weak-crypto --encrypt --user-password=userpass \
 *        --owner-password=ownerpass --bits=N [--use-aes=y|n] -- in.pdf out.pdf
 *
 * @since     2026-08-26
 * @category  Library
 * @package   PdfEncrypt
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2011-2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-encrypt
 */
class InteropTest extends TestUtil
{
    /**
     * Trailer /ID of every qpdf fixture below.
     */
    private const FIXTURE_ID = '318f999d60e15308c50d3e3589aee092';

    /**
     * O entry shared by the R3 and R4 fixtures (same passwords, same algorithm).
     */
    private const FIXTURE_O_128 = '68e5704ac779a5f0cd89704406587a52f25bf61cadc56a0f8db6c4db0052534d';

    /**
     * U entry shared by the R3 and R4 fixtures.
     */
    private const FIXTURE_U_128 = '1add61d559329553a4d2b06b463d8e2a0122456a91bae5134273a6db134c87c4';

    /**
     * File key for the R3 and R4 fixtures, computed from ISO 32000-1 Algorithm 2
     * independently of this library.
     */
    private const FIXTURE_KEY_128 = '38802ceb75dfaa946a6f442a3b48794d';

    private const FIXTURE_O_R6 = '65fcf4e224cec6c61be82a2cadbb5465b5ba29bc84c88ead81cc5b9d0427cd5e06a13d1b97213d05f98c7c50ee85c393';

    private const FIXTURE_U_R6 = 'cba5458dc876d249172916e1f1543ca02727e327b961b2a9b71357961bec1abc97aca669e41d4c6e805912ff4f369a6b';

    private const FIXTURE_OE_R6 = '86822375e5e133e77ec94e2a3b544ebc6aba33fa3e095275ce821e42afebdc7a';

    private const FIXTURE_UE_R6 = 'fa56e7d5c29a93951644630d914fac097039e3e9418504710693290ddc5cb252';

    private const FIXTURE_PERMS_R6 = 'a45e3357757152f242992e4ada7e939c';

    /**
     * Build a Decrypt instance from hexadecimal dictionary fields.
     */
    private function decryptFixture(
        int $version,
        int $length,
        int $mode,
        int $perm,
        string $ohex,
        string $uhex,
        string $oehex = '',
        string $uehex = '',
        string $permshex = '',
        bool $encryptMetadata = true,
    ): Decrypt {
        return new Decrypt([
            'V' => $version,
            'Length' => $length,
            'P' => $perm,
            'mode' => $mode,
            'EncryptMetadata' => $encryptMetadata,
            'fileid' => (string) \hex2bin(self::FIXTURE_ID),
            'O' => (string) \hex2bin($ohex),
            'U' => (string) \hex2bin($uhex),
            'OE' => (string) \hex2bin($oehex),
            'UE' => (string) \hex2bin($uehex),
            'perms' => (string) \hex2bin($permshex),
        ]);
    }

    /**
     * Encryption dictionaries written by qpdf.
     *
     * The expected keys for R2 to R4 were computed from ISO 32000-1 Algorithm 2
     * independently of this library. R6 carries no expected key: the Perms check
     * already confirms the recovered key.
     *
     * @return array<string, array{int, int, int, int, string, string, string, string, string, string}>
     */
    public static function qpdfFixtureProvider(): array
    {
        return [
            'R2 RC4-40' => [
                1,
                40,
                0,
                -4,
                'f86213eb0ced81f097947f3b343e34cac8ca92ce8f6fee2556fa31ec1fe968af',
                'e562aaa3018b40ffb46e79dc277400a5a64a4803925f3fb578ad5944dc250439',
                '',
                '',
                '',
                'a297f9b505',
            ],
            'R3 RC4-128' => [
                2,
                128,
                1,
                -4,
                self::FIXTURE_O_128,
                self::FIXTURE_U_128,
                '',
                '',
                '',
                self::FIXTURE_KEY_128,
            ],
            'R4 AES-128' => [
                4,
                128,
                2,
                -4,
                self::FIXTURE_O_128,
                self::FIXTURE_U_128,
                '',
                '',
                '',
                self::FIXTURE_KEY_128,
            ],
            'R6 AES-256' => [
                5,
                256,
                4,
                -4,
                self::FIXTURE_O_R6,
                self::FIXTURE_U_R6,
                self::FIXTURE_OE_R6,
                self::FIXTURE_UE_R6,
                self::FIXTURE_PERMS_R6,
                '',
            ],
        ];
    }

    #[DataProvider('qpdfFixtureProvider')]
    public function testForeignUserPassword(
        int $version,
        int $length,
        int $mode,
        int $perm,
        string $ohex,
        string $uhex,
        string $oehex,
        string $uehex,
        string $permshex,
        string $expectedKey,
    ): void {
        $dec = $this->decryptFixture($version, $length, $mode, $perm, $ohex, $uhex, $oehex, $uehex, $permshex);
        $this->assertTrue($dec->authenticate('userpass'));
        $this->assertSame('user', $dec->getAuthenticatedRole());

        if ($expectedKey !== '') {
            $this->assertSame($expectedKey, \bin2hex($dec->getDocumentKey()));
        }
    }

    /**
     * A qpdf R4 document written with --cleartext-metadata.
     *
     * The four 0xFF bytes of ISO 32000-1 Algorithm 2 step (f) are the only
     * difference between this fixture and an ordinary R4 one. Its trailer /ID
     * differs from FIXTURE_ID because qpdf generates one per run.
     */
    public function testForeignUnencryptedMetadata(): void
    {
        $fileid = '95174c2dbbcd17ac12c1c4fec826f892';
        $dict = [
            'V' => 4,
            'Length' => 128,
            'P' => -4,
            'mode' => 2,
            'EncryptMetadata' => false,
            'fileid' => (string) \hex2bin($fileid),
            'O' => (string) \hex2bin(self::FIXTURE_O_128),
            'U' => (string) \hex2bin('e42f9a7a9b1d638010161b0b191d0b9f0122456a91bae5134273a6db134c87c4'),
        ];

        // Key computed from Algorithm 2 with the metadata bytes appended,
        // independently of this library.
        $expectedKey = '0b243fa2d7c921883d0bff2e40f0cfb3';

        foreach (['userpass' => 'user', 'ownerpass' => 'owner'] as $password => $role) {
            $dec = new Decrypt($dict);
            $this->assertTrue($dec->authenticate($password), $role);
            $this->assertSame($role, $dec->getAuthenticatedRole());
            $this->assertSame($expectedKey, \bin2hex($dec->getDocumentKey()));
        }

        // The same dictionary read as if the metadata were encrypted yields a
        // different key, so no password authenticates.
        $encrypted = $dict;
        $encrypted['EncryptMetadata'] = true;
        $this->assertFalse((new Decrypt($encrypted))->authenticate('userpass'));
    }

    #[DataProvider('qpdfFixtureProvider')]
    public function testForeignOwnerPassword(
        int $version,
        int $length,
        int $mode,
        int $perm,
        string $ohex,
        string $uhex,
        string $oehex,
        string $uehex,
        string $permshex,
        string $expectedKey,
    ): void {
        $dec = $this->decryptFixture($version, $length, $mode, $perm, $ohex, $uhex, $oehex, $uehex, $permshex);
        $this->assertTrue($dec->authenticate('ownerpass'));
        $this->assertSame('owner', $dec->getAuthenticatedRole());

        if ($expectedKey !== '') {
            $this->assertSame($expectedKey, \bin2hex($dec->getDocumentKey()));
        }
    }

    /** Both passwords unlock the same document key. */
    #[DataProvider('qpdfFixtureProvider')]
    public function testForeignBothPasswordsAgree(
        int $version,
        int $length,
        int $mode,
        int $perm,
        string $ohex,
        string $uhex,
        string $oehex,
        string $uehex,
        string $permshex,
        string $_expectedKey,
    ): void {
        $user = $this->decryptFixture($version, $length, $mode, $perm, $ohex, $uhex, $oehex, $uehex, $permshex);
        $owner = $this->decryptFixture($version, $length, $mode, $perm, $ohex, $uhex, $oehex, $uehex, $permshex);
        $this->assertTrue($user->authenticate('userpass'));
        $this->assertTrue($owner->authenticate('ownerpass'));
        $this->assertSame(\bin2hex($user->getDocumentKey()), \bin2hex($owner->getDocumentKey()));
        $this->assertNotSame('', $user->getDocumentKey());
    }

    #[DataProvider('qpdfFixtureProvider')]
    public function testForeignWrongPassword(
        int $version,
        int $length,
        int $mode,
        int $perm,
        string $ohex,
        string $uhex,
        string $oehex,
        string $uehex,
        string $permshex,
        string $_expectedKey,
    ): void {
        $dec = $this->decryptFixture($version, $length, $mode, $perm, $ohex, $uhex, $oehex, $uehex, $permshex);
        $this->assertFalse($dec->authenticate('nottherightone'));
        $this->assertNull($dec->getAuthenticatedRole());
        $this->assertSame('', $dec->getDocumentKey());
    }

    /** For R5 and R6 the Perms entry rejects a rewritten /P. */
    public function testForeignTamperedPermissionsRejected(): void
    {
        $dec = $this->decryptFixture(
            5,
            256,
            4,
            -1, // the fixture was written with -4
            self::FIXTURE_O_R6,
            self::FIXTURE_U_R6,
            self::FIXTURE_OE_R6,
            self::FIXTURE_UE_R6,
            self::FIXTURE_PERMS_R6,
        );
        $this->assertFalse($dec->authenticate('userpass'));
        $this->assertSame('', $dec->getDocumentKey());
    }

    /** The Perms check also rejects a rewritten /EncryptMetadata. */
    public function testForeignTamperedEncryptMetadataRejected(): void
    {
        $dec = $this->decryptFixture(
            5,
            256,
            4,
            -4,
            self::FIXTURE_O_R6,
            self::FIXTURE_U_R6,
            self::FIXTURE_OE_R6,
            self::FIXTURE_UE_R6,
            self::FIXTURE_PERMS_R6,
            false, // the fixture was written with true
        );
        $this->assertFalse($dec->authenticate('userpass'));
    }

    // -------------------------------------------------------------------------
    // Reference implementation for revision 3 short keys
    // -------------------------------------------------------------------------

    /**
     * Padding string from ISO 32000-1 Table 21.
     */
    private const REFPAD =
        "\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4E\x56\xFF\xFA\x01\x08"
            . "\x2E\x2E\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A";

    /**
     * Reference RC4, written from the algorithm rather than reused from src/.
     */
    private function refRc4(string $data, string $key): string
    {
        /** @var array<int, int> $sbox */
        $sbox = \range(0, 255);
        $keylen = \strlen($key);
        $jdx = 0;
        for ($idx = 0; $idx < 256; ++$idx) {
            $val = $sbox[$idx] ?? 0;
            $jdx = ($jdx + $val + \ord($key[$idx % $keylen])) % 256;
            $sbox[$idx] = $sbox[$jdx] ?? 0;
            $sbox[$jdx] = $val;
        }

        $idx = 0;
        $jdx = 0;
        $out = '';
        for ($pos = 0, $len = \strlen($data); $pos < $len; ++$pos) {
            $idx = ($idx + 1) % 256;
            $val = $sbox[$idx] ?? 0;
            $jdx = ($jdx + $val) % 256;
            $sbox[$idx] = $sbox[$jdx] ?? 0;
            $sbox[$jdx] = $val;
            $keybyte = $sbox[(($sbox[$idx] ?? 0) + ($sbox[$jdx] ?? 0)) % 256] ?? 0;
            $out .= \chr(\ord($data[$pos]) ^ $keybyte);
        }

        return $out;
    }

    /** Algorithm 2 step (a): pad or truncate the password to 32 bytes. */
    private function refPad32(#[\SensitiveParameter] string $password): string
    {
        return \substr($password . self::REFPAD, 0, 32);
    }

    /** XOR every byte of $key with $round, as Algorithms 3 and 5 require. */
    private function refXorKey(string $key, int $round, int $keylen): string
    {
        $xored = '';
        for ($pos = 0; $pos < $keylen; ++$pos) {
            $xored .= \chr(\ord($key[$pos]) ^ $round);
        }

        return $xored;
    }

    /** ISO 32000-1 Algorithm 3: compute the O value for revision 3. */
    private function refOValue(string $ownerPass, string $userPass, int $keylen): string
    {
        $hash = \md5($this->refPad32($ownerPass), true);
        // Step (c) re-hashes the full digest, unlike Algorithm 2 step (h).
        for ($idx = 0; $idx < 50; ++$idx) {
            $hash = \md5($hash, true);
        }

        $rc4key = \substr($hash, 0, $keylen);
        $oval = $this->refRc4($this->refPad32($userPass), $rc4key);
        for ($idx = 1; $idx <= 19; ++$idx) {
            $oval = $this->refRc4($oval, $this->refXorKey($rc4key, $idx, $keylen));
        }

        return $oval;
    }

    /** ISO 32000-1 Algorithm 2: compute the file key for revision 3. */
    private function refFileKey(string $userPass, string $oval, int $perm, string $fileid, int $keylen): string
    {
        $hash = \md5($this->refPad32($userPass) . $oval . \pack('V', $perm & 0xFFFFFFFF) . $fileid, true);
        // Step (h) re-hashes only the first n bytes.
        for ($idx = 0; $idx < 50; ++$idx) {
            $hash = \md5(\substr($hash, 0, $keylen), true);
        }

        return \substr($hash, 0, $keylen);
    }

    /** ISO 32000-1 Algorithm 5: compute the U value for revision 3. */
    private function refUValue(string $key, string $fileid, int $keylen): string
    {
        $uval = $this->refRc4(\md5(self::REFPAD . $fileid, true), $key);
        // Step (e) iterates over the file key, whose length is not the digest length.
        for ($idx = 1; $idx <= 19; ++$idx) {
            $uval = $this->refRc4($uval, $this->refXorKey($key, $idx, $keylen));
        }

        return \substr($uval . \str_repeat("\x00", 16), 0, 32);
    }

    /**
     * Revision 3 permits key lengths from 40 to 128 bits; this library writes 128.
     *
     * @return array<string, array{int<40, 128>, string, string}>
     */
    public static function shortKeyProvider(): array
    {
        $cases = [];
        foreach ([40, 56, 80, 120, 128] as $bits) {
            foreach (['userpass' => 'user', 'ownerpass' => 'owner'] as $password => $role) {
                $cases[$bits . ' bit, ' . $role] = [$bits, $password, $role];
            }
        }

        return $cases;
    }

    #[DataProvider('shortKeyProvider')]
    public function testRevisionThreeShortKeys(int $bits, #[\SensitiveParameter] string $password, string $role): void
    {
        $keylen = \intdiv($bits, 8);
        $fileid = \md5('short-key-fixture', true);
        $perm = -8;

        $oval = $this->refOValue('ownerpass', 'userpass', $keylen);
        $expectedKey = $this->refFileKey('userpass', $oval, $perm, $fileid, $keylen);
        $uval = $this->refUValue($expectedKey, $fileid, $keylen);

        $dec = new Decrypt([
            'V' => 2,
            'Length' => $bits,
            'P' => $perm,
            'mode' => 1,
            'fileid' => $fileid,
            'O' => $oval,
            'U' => $uval,
        ]);
        $this->assertTrue($dec->authenticate($password));
        $this->assertSame($role, $dec->getAuthenticatedRole());
        $this->assertSame(\bin2hex($expectedKey), \bin2hex($dec->getDocumentKey()));
    }

    // -------------------------------------------------------------------------
    // Reference implementation for revision 5
    // -------------------------------------------------------------------------

    /**
     * AES-256 with a zero IV and no block padding, as Algorithms 8, 9 and 10 use.
     */
    private function refAesNoPad(string $data, string $key): string
    {
        $enc = \openssl_encrypt(
            $data,
            'aes-256-cbc',
            $key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            \str_repeat("\x00", 16),
        );
        $this->assertNotFalse($enc);
        return $enc;
    }

    /**
     * Build a complete revision 5 dictionary from Adobe Extension Level 3,
     * written from the algorithm rather than reused from src/.
     *
     * @return array{O: string, U: string, OE: string, UE: string, perms: string, key: string}
     */
    private function refRevisionFive(string $userPass, string $ownerPass, string $key, int $perm): array
    {
        // Fixed salts, so that the fixture is reproducible.
        $uvs = "\x01\x02\x03\x04\x05\x06\x07\x08";
        $uks = "\x11\x12\x13\x14\x15\x16\x17\x18";
        $ovs = "\x21\x22\x23\x24\x25\x26\x27\x28";
        $oks = "\x31\x32\x33\x34\x35\x36\x37\x38";

        $uval = \hash('sha256', $userPass . $uvs, true) . $uvs . $uks;
        $ueval = $this->refAesNoPad($key, \hash('sha256', $userPass . $uks, true));
        $oval = \hash('sha256', $ownerPass . $ovs . $uval, true) . $ovs . $oks;
        $oeval = $this->refAesNoPad($key, \hash('sha256', $ownerPass . $oks . $uval, true));

        $permsblock = \pack('V', $perm & 0xFFFFFFFF) . "\xFF\xFF\xFF\xFF" . 'T' . 'adb' . "\x00\x01\x02\x03";

        return [
            'O' => $oval,
            'U' => $uval,
            'OE' => $oeval,
            'UE' => $ueval,
            'perms' => $this->refAesNoPad($permsblock, $key),
            'key' => $key,
        ];
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function roleProvider(): array
    {
        return [
            'user' => ['userpass', 'user'],
            'owner' => ['ownerpass', 'owner'],
        ];
    }

    /**
     * qpdf does not write revision 5, so these vectors come from Adobe
     * Extension Level 3 instead of a foreign fixture.
     */
    #[DataProvider('roleProvider')]
    public function testRevisionFiveAgainstSpecificationVectors(
        #[\SensitiveParameter]
        string $password,
        string $role,
    ): void {
        $key = \str_repeat("\x5A", 32);
        $perm = -3904;
        $ref = $this->refRevisionFive('userpass', 'ownerpass', $key, $perm);

        $dec = new Decrypt([
            'V' => 5,
            'Length' => 256,
            'P' => $perm,
            'mode' => 3,
            'fileid' => '',
            'O' => $ref['O'],
            'U' => $ref['U'],
            'OE' => $ref['OE'],
            'UE' => $ref['UE'],
            'perms' => $ref['perms'],
        ]);
        $this->assertTrue($dec->authenticate($password));
        $this->assertSame($role, $dec->getAuthenticatedRole());
        $this->assertSame(\bin2hex($key), \bin2hex($dec->getDocumentKey()));
    }

    /** The same vectors are rejected once /P no longer matches /Perms. */
    public function testRevisionFiveTamperedPermissionsRejected(): void
    {
        $ref = $this->refRevisionFive('userpass', 'ownerpass', \str_repeat("\x5A", 32), -3904);
        $dec = new Decrypt([
            'V' => 5,
            'Length' => 256,
            'P' => -1,
            'mode' => 3,
            'fileid' => '',
            'O' => $ref['O'],
            'U' => $ref['U'],
            'OE' => $ref['OE'],
            'UE' => $ref['UE'],
            'perms' => $ref['perms'],
        ]);
        $this->assertFalse($dec->authenticate('userpass'));
        $this->assertSame('', $dec->getDocumentKey());
    }

    // -------------------------------------------------------------------------
    // Encryption side: the bytes this library writes
    // -------------------------------------------------------------------------

    /**
     * The revision 4 entries this library writes, against the reference
     * implementation above.
     */
    public function testRevisionFourOutputMatchesSpecification(): void
    {
        $fileidHex = \md5('encrypt-side-fixture');
        $fileid = (string) \hex2bin($fileidHex);
        $enc = new Encrypt(true, $fileidHex, 2, ['print'], 'userpass', 'ownerpass');
        $data = $enc->getEncryptionData();

        $oval = $this->refOValue('ownerpass', 'userpass', 16);
        $key = $this->refFileKey('userpass', $oval, $data['P'], $fileid, 16);
        $uval = $this->refUValue($key, $fileid, 16);

        $this->assertSame(\bin2hex($oval), \bin2hex($data['O']));
        $this->assertSame(\bin2hex($uval), \bin2hex($data['U']));
        $this->assertSame(\bin2hex($key), \bin2hex($data['key']));
    }

    /**
     * Every revision 5 entry, recomputed from the salts the library chose and
     * compared against Adobe Extension Level 3.
     */
    public function testRevisionFiveOutputMatchesSpecification(): void
    {
        $enc = new Encrypt(true, \md5('encrypt-side-fixture'), 3, ['print'], 'userpass', 'ownerpass');
        $data = $enc->getEncryptionData();
        $key = $data['key'];
        $uval = $data['U'];

        $uvs = \substr($uval, 32, 8);
        $uks = \substr($uval, 40, 8);
        $ovs = \substr($data['O'], 32, 8);
        $oks = \substr($data['O'], 40, 8);

        $this->assertSame(\bin2hex(\hash('sha256', 'userpass' . $uvs, true)), \bin2hex(\substr($uval, 0, 32)));
        $this->assertSame(
            \bin2hex($this->refAesNoPad($key, \hash('sha256', 'userpass' . $uks, true))),
            \bin2hex($data['UE']),
        );
        $this->assertSame(
            \bin2hex(\hash('sha256', 'ownerpass' . $ovs . $uval, true)),
            \bin2hex(\substr($data['O'], 0, 32)),
        );
        $this->assertSame(
            \bin2hex($this->refAesNoPad($key, \hash('sha256', 'ownerpass' . $oks . $uval, true))),
            \bin2hex($data['OE']),
        );

        // Algorithm 10: the Perms block encrypted under the file key.
        $plain = \openssl_decrypt(
            $data['perms'],
            'aes-256-cbc',
            $key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            \str_repeat("\x00", 16),
        );
        $this->assertNotFalse($plain);
        $this->assertSame(\pack('V', $data['P'] & 0xFFFFFFFF), \substr($plain, 0, 4));
        $this->assertSame("\xFF\xFF\xFF\xFF", \substr($plain, 4, 4));
        $this->assertSame('T', $plain[8]);
        $this->assertSame('adb', \substr($plain, 9, 3));
    }

    /**
     * Algorithm 2.B known-answer vector with a chosen salt.
     *
     * The salt is chosen so that the loop runs past its minimum of 64 rounds:
     * with this input the termination byte is above the threshold at rounds 64
     * to 66, and the hash settles at round 67.
     */
    public function testAlgorithmTwoBFixedSaltVector(): void
    {
        $input = 'algorithm 2.B vector';
        $salt = (string) \hex2bin('3261b4a8fbe54b47');
        $expected = 'beaf7f0d4fee0ca261d70dc2115543c25ece711d9d12af8e26b10b365b421176';

        $probe = new Algorithm2BProbe();

        $this->assertSame($expected, \bin2hex($probe->hashOf($input, $salt)));
        $this->assertSame($expected, \bin2hex($this->refHash2B($input, $salt)));
    }

    /**
     * ISO 32000-2 section 7.6.4.3.4 Algorithm 2.B, written from the
     * specification rather than reused from src/.
     *
     * Step (c) reads the first 16 bytes of the AES output as one unsigned
     * big-endian integer and takes it modulo 3.
     */
    private function refHash2B(#[\SensitiveParameter] string $password, string $salt, string $userHash = ''): string
    {
        $hashK = \hash('sha256', $password . $salt . $userHash, true);
        $enc = '';
        for ($round = 0; $round < 64 || \ord($enc[\strlen($enc) - 1]) > ($round - 32); ++$round) {
            $encrypted = \openssl_encrypt(
                \str_repeat($password . $hashK . $userHash, 64),
                'aes-128-cbc',
                \substr($hashK, 0, 16),
                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
                \substr($hashK, 16, 16),
            );
            if ($encrypted === false) {
                $this->fail('the reference AES-128-CBC step failed');
            }

            $enc = $encrypted;

            $remainder = 0;
            for ($idx = 0; $idx < 16; ++$idx) {
                $remainder = (($remainder * 256) + \ord($enc[$idx])) % 3;
            }

            $hashK = \hash(
                match ($remainder) {
                    0 => 'sha256',
                    1 => 'sha384',
                    default => 'sha512',
                },
                $enc,
                true,
            );
        }

        return \substr($hashK, 0, 32);
    }

    /** The same for revision 6, whose password hash is Algorithm 2.B. */
    public function testRevisionSixOutputMatchesSpecification(): void
    {
        $enc = new Encrypt(true, \md5('encrypt-side-fixture'), 4, ['print'], 'userpass', 'ownerpass');
        $data = $enc->getEncryptionData();
        $key = $data['key'];
        $uval = $data['U'];

        $uvs = \substr($uval, 32, 8);
        $uks = \substr($uval, 40, 8);
        $ovs = \substr($data['O'], 32, 8);
        $oks = \substr($data['O'], 40, 8);

        $this->assertSame(\bin2hex($this->refHash2B('userpass', $uvs)), \bin2hex(\substr($uval, 0, 32)));
        $this->assertSame(
            \bin2hex($this->refAesNoPad($key, $this->refHash2B('userpass', $uks))),
            \bin2hex($data['UE']),
        );
        $this->assertSame(\bin2hex($this->refHash2B('ownerpass', $ovs, $uval)), \bin2hex(\substr($data['O'], 0, 32)));
        $this->assertSame(
            \bin2hex($this->refAesNoPad($key, $this->refHash2B('ownerpass', $oks, $uval))),
            \bin2hex($data['OE']),
        );
    }

    /** With the random source pinned, the whole dictionary is reproducible byte for byte. */
    public function testFrozenSeedProducesTheExpectedRevisionFiveDictionary(): void
    {
        $enc = new DeterministicEncrypt(true, \md5('kat'), 3, ['print'], 'userpass', 'ownerpass');
        $data = $enc->getEncryptionData();

        $this->assertSame('70674a725e8a833a16337075a01937009565fa89dcdfadf11529c7149312313c', \bin2hex($data['key']));
        $this->assertSame(
            '4cd31bbdb787ed5fb722903e1e122e151af8039e43c67f5e134f5f0747a59e6f' . '036fa5b2d8027e443eb32a70dace7de8',
            \bin2hex($data['U']),
        );
        $this->assertSame('f5bfc7e128b0aea23b4ad0e2574194e11fbbc94947f0fea507e09f1d9acbe46c', \bin2hex($data['UE']));
        $this->assertSame(
            '261f93fb622fcb5e99e93373fd19f130a306f0037e03d3163ce6715ecad1ffd0' . '2942b99da77429eeb86767ec1bde925b',
            \bin2hex($data['O']),
        );
        $this->assertSame('24f81ea8781ae0e126667db5c4351419d251597e3f9fee39f7f7ad21345325e6', \bin2hex($data['OE']));
        $this->assertSame('38f1dac54f2cf35705ac098dc8b2a14d', \bin2hex($data['perms']));

        // The same two entries, recomputed from the salts the fixture carries,
        // following Adobe Extension Level 3 Algorithms 8 and 9.
        $uval = \hash('sha256', 'userpass' . \substr($data['U'], 32, 8), true) . \substr($data['U'], 32, 16);
        $this->assertSame(\bin2hex($uval), \bin2hex($data['U']));
        $this->assertSame(
            \bin2hex(\hash('sha256', 'ownerpass' . \substr($data['O'], 32, 8) . $uval, true)),
            \bin2hex(\substr($data['O'], 0, 32)),
        );
    }

    /** The same frozen-seed dictionary for revision 6. */
    public function testFrozenSeedProducesTheExpectedRevisionSixDictionary(): void
    {
        $enc = new DeterministicEncrypt(true, \md5('kat'), 4, ['print'], 'userpass', 'ownerpass');
        $data = $enc->getEncryptionData();

        $this->assertSame('70674a725e8a833a16337075a01937009565fa89dcdfadf11529c7149312313c', \bin2hex($data['key']));
        $this->assertSame(
            'f770972a5cf0392377860a6e6d466e55065d033119834d858f7916d90d710710' . '036fa5b2d8027e443eb32a70dace7de8',
            \bin2hex($data['U']),
        );
        $this->assertSame('dce9d292203c654986b17e371129e548aba22d46114d2e7572b29ee152f67f93', \bin2hex($data['UE']));
        $this->assertSame(
            '0beb921148d38493a586e9c952b29673c5fe1fd883d51c6a722d8a0120318cff' . '2942b99da77429eeb86767ec1bde925b',
            \bin2hex($data['O']),
        );
        $this->assertSame('3ee1df3ccf3b3beca5339bd9ba51042ab35c3624716ba4c0a2b492e361fcb3e3', \bin2hex($data['OE']));
        $this->assertSame('38f1dac54f2cf35705ac098dc8b2a14d', \bin2hex($data['perms']));

        $dec = new Decrypt($data);
        $this->assertTrue($dec->authenticate('userpass'));
        $this->assertSame(\bin2hex($data['key']), \bin2hex($dec->getDocumentKey()));
    }

    /** The two AES-256 salts are the first 16 bytes of the seed, in order. */
    public function testAes256SaltsComeStraightFromTheSeed(): void
    {
        $enc = new DeterministicEncrypt(true, \md5('kat'), 3, ['print'], 'userpass', 'ownerpass');
        $data = $enc->getEncryptionData();

        // Seeds 2 and 3 of the frozen sequence, whose first 16 bytes are the
        // validation salt followed by the key salt.
        $userSeed = \hash('sha512', 'tc-lib-pdf-encrypt fixed seed 2', true);
        $ownerSeed = \hash('sha512', 'tc-lib-pdf-encrypt fixed seed 3', true);

        $this->assertSame(\bin2hex(\substr($userSeed, 0, 16)), \bin2hex(\substr($data['U'], 32, 16)));
        $this->assertSame(\bin2hex(\substr($ownerSeed, 0, 16)), \bin2hex(\substr($data['O'], 32, 16)));
    }

    /**
     * The permission bytes of a public-key envelope are stored high-order byte
     * first, at offset 20, the opposite of the /P key material.
     */
    public function testPublicKeyEnvelopeCarriesBigEndianPermissions(): void
    {
        $certPath = __DIR__ . '/data/cert.pem';
        $enc = new Encrypt(true, \md5('pubkey-fixture'), 3, pubkeys: [
            ['c' => $certPath, 'p' => ['print', 'copy']],
        ]);
        $expected = $enc->getUserPermissionCode(['print', 'copy'], 3);

        $recipient = $enc->getEncryptionData()['Recipients'][0] ?? '';
        $this->assertNotSame('', $recipient);

        $envelope = $this->decryptOwnRecipientEnvelope($recipient, $certPath);
        $this->assertSame(24, \strlen($envelope));
        $this->assertSame(\bin2hex(\pack('N', $expected & 0xFFFFFFFF)), \bin2hex(\substr($envelope, 20, 4)));

        // Decrypt reads them back as the same signed value.
        $dec = new Decrypt($enc->getEncryptionData());
        $this->assertTrue($dec->authenticate('', $certPath));
        $this->assertSame('recipient', $dec->getAuthenticatedRole());
        $this->assertSame($expected, $dec->getRecipientPermissions());
    }

    /**
     * Unwrap one of this library's PKCS#7 recipient envelopes with OpenSSL
     * directly, without going through Decrypt.
     */
    private function decryptOwnRecipientEnvelope(string $hexRecipient, string $certPath): string
    {
        $smime =
            "MIME-Version: 1.0\r\n"
            . "Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\r\n"
            . "Content-Transfer-Encoding: base64\r\n\r\n"
            . \chunk_split(\base64_encode((string) \hex2bin($hexRecipient)));

        $tmpIn = (string) \tempnam(\sys_get_temp_dir(), 'tclpe_in_');
        $tmpOut = (string) \tempnam(\sys_get_temp_dir(), 'tclpe_out_');

        try {
            \file_put_contents($tmpIn, $smime);
            $pem = (string) \file_get_contents($certPath);
            $this->assertTrue(\openssl_pkcs7_decrypt($tmpIn, $tmpOut, $pem, $pem));
            return (string) \file_get_contents($tmpOut);
        } finally {
            \unlink($tmpIn);
            \unlink($tmpOut);
        }
    }
}
