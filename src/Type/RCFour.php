<?php
/**
 * RCFour.php
 *
 * @since       2011-05-23
 * @category    Library
 * @package     PdfEncrypt
 * @author      Nicola Asuni <info@tecnick.com>
 * @copyright   2011-2015 Nicola Asuni - Tecnick.com LTD
 * @license     http://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE.TXT)
 * @link        https://github.com/tecnickcom/tc-lib-pdf-encrypt
 *
 * This file is part of tc-lib-pdf-encrypt software library.
 */

namespace Com\Tecnick\Pdf\Encrypt\Type;

use \Com\Tecnick\Pdf\Encrypt\Exception as EncException;

/**
 * Com\Tecnick\Pdf\Encrypt\Type\RCFour
 *
 * RC4 is the standard encryption algorithm used in PDF format
 *
 * @since       2011-05-23
 * @category    Library
 * @package     PdfEncrypt
 * @author      Nicola Asuni <info@tecnick.com>
 * @copyright   2011-2015 Nicola Asuni - Tecnick.com LTD
 * @license     http://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE.TXT)
 * @link        https://github.com/tecnickcom/tc-lib-pdf-encrypt
 */
class RCFour
{
    /**
     * Encrypt the data
     *
     * @param string $data Data string to encrypt
     * @param string $key  Encryption key
     * @param string $mode Default mode (mcrypt or raw)
     *
     * @return string Encrypted data string.
     */
    public function encrypt($data, $key, $mode = 'mcrypt')
    {
        if (($mode == 'mcrypt') && function_exists('mcrypt_encrypt') && ($out = $this->encryptMcrypt($data, $key))) {
            return $out;
        }
        return $this->encryptRaw($data, $key);
    }

    /**
     * Encrypt the data using Mcrypt
     *
     * @param string $data Data string to encrypt
     * @param string $key  Encryption key
     *
     * @return string Encrypted data string.
     */
    public function encryptMcrypt($data, $key)
    {
        return mcrypt_encrypt(MCRYPT_ARCFOUR, $key, $data, MCRYPT_MODE_STREAM, '');
    }

    /**
     * Encrypt the data using raw code
     *
     * @param string $data Data string to encrypt
     * @param string $key  Encryption key
     *
     * @return string Encrypted data string.
     */
    public function encryptRaw($data, $key)
    {
        $kdx = str_repeat($key, ((256 / strlen($key)) + 1));
        $rc4 = range(0, 255);
        $jdx = 0;
        for ($idx = 0; $idx < 256; ++$idx) {
            $tdx = $rc4[$idx];
            $jdx = (($jdx + $tdx + ord($kdx[$idx])) % 256);
            $rc4[$idx] = $rc4[$jdx];
            $rc4[$jdx] = $tdx;
        }
        $len = strlen($data);
        $adx = 0;
        $bdx = 0;
        $out = '';
        for ($idx = 0; $idx < $len; ++$idx) {
            $adx = (($adx + 1) % 256);
            $tdx = $rc4[$adx];
            $bdx = (($bdx + $tdx) % 256);
            $rc4[$adx] = $rc4[$bdx];
            $rc4[$bdx] = $tdx;
            $kdx = $rc4[($rc4[$adx] + $rc4[$bdx]) % 256];
            $out .= chr(ord($data[$idx]) ^ $kdx);
        }
        return $out;
    }
}
