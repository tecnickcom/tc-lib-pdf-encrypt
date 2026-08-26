<?php

declare(strict_types=1);

/**
 * check-readers.php
 *
 * Writes one encrypted PDF per mode, with and without metadata encryption, and
 * checks that qpdf and mutool open it with both the user and the owner password.
 *
 * Requires qpdf and mutool on PATH. Exits non-zero when a check fails.
 *
 * Usage: php resources/interop/check-readers.php
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

use Com\Tecnick\Pdf\Encrypt\Encrypt;

require_once __DIR__ . '/../../vendor/autoload.php';

const USER_PASS = 'userpass';
const OWNER_PASS = 'ownerpass';
const WRONG_PASS = 'not-the-password';
const PAGE_TEXT = 'hello encrypted world';
const XMP_MARKER = '<dc:title>probe';

$failures = [];
$checks = 0;

/**
 * Build a complete encrypted PDF and return its bytes.
 */
function buildPdf(int $mode, bool $encryptMetadata): string
{
    $enc = new Encrypt(
        enabled: true,
        file_id: \md5('interop-' . $mode . '-' . ($encryptMetadata ? 'em' : 'noem')),
        mode: $mode,
        permissions: ['modify'],
        user_pass: USER_PASS,
        owner_pass: OWNER_PASS,
        encryptMetadata: $encryptMetadata,
    );

    $content = 'BT /F1 24 Tf 72 700 Td (' . PAGE_TEXT . ') Tj ET';
    $stream = $enc->encryptString($content, 4);

    $xmp = '<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
        . '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF '
        . 'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        . '<rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/">'
        . XMP_MARKER . '</dc:title></rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>';
    // The metadata stream follows the effective EncryptMetadata flag.
    $metadata = $enc->getEncryptionData()['EncryptMetadata'] ? $enc->encryptString($xmp, 6) : $xmp;

    $objects = [
        1 => "<< /Type /Catalog /Pages 2 0 R /Metadata 6 0 R >>",
        2 => "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3 => "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            . "/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        4 => '<< /Length ' . \strlen($stream) . " >>\nstream\n" . $stream . "\nendstream",
        5 => "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        6 => '<< /Type /Metadata /Subtype /XML /Length ' . \strlen($metadata) . " >>\nstream\n"
            . $metadata . "\nendstream",
    ];

    $out = "%PDF-1.7\n%\xE2\xE3\xCF\xD3\n";
    $offsets = [];
    foreach ($objects as $num => $body) {
        $offsets[$num] = \strlen($out);
        $out .= $num . " 0 obj\n" . $body . "\nendobj\n";
    }

    // The encryption dictionary is never itself encrypted.
    $pon = 6;
    $offsets[7] = \strlen($out);
    $out .= $enc->getPdfEncryptionObj($pon);

    $offsets[8] = \strlen($out);
    $out .= "8 0 obj\n<< /Producer " . $enc->escapeDataString('probe producer', 8)
        . ' /Title ' . $enc->escapeDataString('probe title', 8) . " >>\nendobj\n";

    $xrefpos = \strlen($out);
    $out .= "xref\n0 9\n0000000000 65535 f \n";
    for ($num = 1; $num <= 8; ++$num) {
        $out .= \sprintf("%010d 00000 n \n", $offsets[$num]);
    }

    $fileid = $enc->getFileId();
    $out .= "trailer\n<< /Size 9 /Root 1 0 R /Encrypt 7 0 R /Info 8 0 R "
        . '/ID [<' . $fileid . '><' . $fileid . ">] >>\nstartxref\n" . $xrefpos . "\n%%EOF\n";

    return $out;
}

/**
 * Run a command and return [exitCode, combined output].
 *
 * @param array<string> $cmd
 *
 * @return array{0: int, 1: string}
 */
function run(array $cmd): array
{
    $escaped = \implode(' ', \array_map('\escapeshellarg', $cmd)) . ' 2>&1';
    $lines = [];
    $code = 0;
    \exec($escaped, $lines, $code);
    return [$code, \implode("\n", $lines)];
}

function requireTool(string $tool): void
{
    [$code] = run(['which', $tool]);
    if ($code !== 0) {
        \fwrite(\STDERR, 'required tool not found on PATH: ' . $tool . \PHP_EOL);
        exit(2);
    }
}

requireTool('qpdf');
requireTool('mutool');

$tmpdir = \sys_get_temp_dir() . '/tc-lib-pdf-encrypt-interop-' . \getmypid();
// The name is predictable, so an existing directory is not reused.
if (!\mkdir($tmpdir, 0o700, true)) {
    \fwrite(\STDERR, 'cannot create ' . $tmpdir . \PHP_EOL);
    exit(2);
}

\register_shutdown_function(static function () use ($tmpdir): void {
    \array_map('\unlink', \glob($tmpdir . '/*.pdf') ?: []);
    @\rmdir($tmpdir);
});

foreach ([0, 1, 2, 3, 4] as $mode) {
    foreach ([true, false] as $encryptMetadata) {
        $label = 'mode ' . $mode . ' encryptMetadata=' . ($encryptMetadata ? 'true' : 'false');
        // Modes 0 and 1 report that RC4 is deprecated and that they cannot
        // express unencrypted metadata; every other diagnostic is collected.
        $unexpected = [];
        $rc4 = $mode <= 1;
        $metadataRefused = $rc4 && !$encryptMetadata;
        \set_error_handler(
            static function (int $severity, string $message) use (&$unexpected, $rc4, $metadataRefused): bool {
                $expected = ($rc4 && $severity === E_USER_DEPRECATED && \str_starts_with($message, 'RC4 encryption'))
                    || ($metadataRefused
                        && $severity === E_USER_WARNING
                        && \str_starts_with($message, 'Unencrypted metadata requires AES'));
                if (!$expected) {
                    $unexpected[] = $message;
                }

                return true;
            },
        );

        try {
            $pdf = buildPdf($mode, $encryptMetadata);
        } finally {
            \restore_error_handler();
        }

        ++$checks;
        foreach ($unexpected as $message) {
            $failures[] = $label . ': unexpected diagnostic while building: ' . $message;
        }
        $path = $tmpdir . '/m' . $mode . ($encryptMetadata ? 'em' : 'noem') . '.pdf';
        \file_put_contents($path, $pdf);

        foreach ([USER_PASS => 'user', OWNER_PASS => 'owner'] as $password => $role) {
            $context = $label . ' [' . $role . ' password]';

            ++$checks;
            [$code, $output] = run(['qpdf', '--check', '--password=' . $password, $path]);
            if ($code !== 0) {
                $failures[] = $context . ': qpdf --check failed: ' . $output;
            }

            ++$checks;
            [$code, $output] = run(['qpdf', '--show-encryption', '--password=' . $password, $path]);
            if ($code !== 0 || !\str_contains($output, 'Supplied password is ' . $role . ' password')) {
                $failures[] = $context . ': qpdf did not recognise the ' . $role . ' password: ' . $output;
            }

            ++$checks;
            [$code, $output] = run(['mutool', 'draw', '-p', $password, '-F', 'txt', $path]);
            if ($code !== 0 || !\str_contains($output, PAGE_TEXT)) {
                $failures[] = $context . ': mutool did not render the page text: ' . $output;
            }

            ++$checks;
            [$code, $output] = run([
                'qpdf',
                '--show-object=8',
                '--password=' . $password,
                $path,
            ]);
            if ($code !== 0 || !\str_contains($output, '(probe title)')) {
                $failures[] = $context . ': the encrypted Info strings did not decrypt: ' . $output;
            }

            // The metadata stream must read back through the reader.
            ++$checks;
            [$code, $output] = run([
                'qpdf',
                '--show-object=6',
                '--filtered-stream-data',
                '--password=' . $password,
                $path,
            ]);
            if ($code !== 0 || !\str_contains($output, XMP_MARKER)) {
                $failures[] = $context . ': the metadata stream did not read back: ' . $output;
            }
        }

        // Negative checks: a wrong password must not open the document, and the
        // page text must not appear in the clear.
        ++$checks;
        [$code, $output] = run(['qpdf', '--check', '--password=' . WRONG_PASS, $path]);
        if ($code === 0) {
            $failures[] = $label . ': qpdf opened the document with a wrong password: ' . $output;
        }

        ++$checks;
        $raw = (string) \file_get_contents($path);
        if (\str_contains($raw, PAGE_TEXT)) {
            $failures[] = $label . ': the page text appears verbatim in the encrypted file';
        }

        // Modes 0 and 1 encrypt the metadata whatever was requested, so the
        // expectation follows the effective flag.
        ++$checks;
        $metadataEncrypted = $encryptMetadata || $rc4;
        $metadataVisible = \str_contains($raw, XMP_MARKER);
        if ($metadataVisible === $metadataEncrypted) {
            $failures[] = $label . ($metadataVisible
                ? ': the metadata appears verbatim in the encrypted file'
                : ': the metadata was encrypted although the document declares it is not');
        }

        echo '  checked ', $label, \PHP_EOL;
    }
}

if ($failures !== []) {
    \fwrite(\STDERR, \PHP_EOL . \count($failures) . ' of ' . $checks . ' checks failed:' . \PHP_EOL);
    foreach ($failures as $failure) {
        \fwrite(\STDERR, '  - ' . $failure . \PHP_EOL);
    }

    exit(1);
}

echo \PHP_EOL, 'all ', $checks, ' reader checks passed', \PHP_EOL;
