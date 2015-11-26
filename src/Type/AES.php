<?php
/**
 * AES.php
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
 * Com\Tecnick\Pdf\Encrypt\Type\AES
 *
 * AES
 *
 * @since       2011-05-23
 * @category    Library
 * @package     PdfEncrypt
 * @author      Nicola Asuni <info@tecnick.com>
 * @copyright   2011-2015 Nicola Asuni - Tecnick.com LTD
 * @license     http://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE.TXT)
 * @link        https://github.com/tecnickcom/tc-lib-pdf-encrypt
 */
class AES extends AESnopad
{
    /**
     * Encrypt the data using OpenSSL
     *
     * @param string $data Data string to encrypt
     * @param string $key  Encryption key
     * @param string $ivect Initialization vector (ignored)
     *
     * @return string Encrypted data string.
     */
    protected function encryptOpenSsl($data, $key, $ivect = self::IVECT)
    {
        $ivect = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        return $ivect.parent::encryptOpenSsl($data, $key, $ivect);
    }
    
    /**
     * Encrypt the data using Mcrypt
     *
     * @param string $data Data string to encrypt
     * @param string $key  Encryption key
     * @param string $ivect Initialization vector (ignored)
     *
     * @return string Encrypted data string.
     */
    protected function encryptMcrypt($data, $key, $ivect = self::IVECT)
    {
        $ivect = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC), MCRYPT_RAND);
        return $ivect.parent::encryptMcrypt($data, $key, $ivect);
    }
}
