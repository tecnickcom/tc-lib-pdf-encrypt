<?php

/**
 * AES.php
 *
 * @since     2011-05-23
 * @category  Library
 * @package   PdfEncrypt
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2011-2023 Nicola Asuni - Tecnick.com LTD
 * @license   http://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE.TXT)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-encrypt
 *
 * This file is part of tc-lib-pdf-encrypt software library.
 */

namespace Com\Tecnick\Pdf\Encrypt\Type;

use Com\Tecnick\Pdf\Encrypt\Exception as EncException;

/**
 * Com\Tecnick\Pdf\Encrypt\Type\AES
 *
 * AES
 *
 * @since     2011-05-23
 * @category  Library
 * @package   PdfEncrypt
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2011-2023 Nicola Asuni - Tecnick.com LTD
 * @license   http://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE.TXT)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-encrypt
 */
class AES
{
    /**
     * Encrypt the data using OpenSSL
     *
     * @param string $data Data string to encrypt
     * @param string $key  Encryption key
     * @param string $mode Cipher
     */
    public function encrypt(string $data, string $key, string $mode = ''): string
    {
        if ($mode === '') {
            $mode = strlen($key) > 16 ? 'aes-256-cbc' : 'aes-128-cbc';
        } elseif (! in_array($mode, ['aes-128-cbc', 'aes-256-cbc'])) {
            throw new EncException('unknown chipher: ' . $mode);
        }

        $len = openssl_cipher_iv_length($mode);
        if ($len === false) {
            throw new EncException('openssl_cipher_iv_length failed');
        }

        $ivect = openssl_random_pseudo_bytes($len);
        $aeSnopad = new AESnopad();
        return $ivect . $aeSnopad->encrypt($data, $key, $ivect, $mode);
    }
}
