<?php
/**
 * AESTest.php
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

namespace Test;

/**
 * AES encryption Test
 *
 * @since       2011-05-23
 * @category    Library
 * @package     PdfEncrypt
 * @author      Nicola Asuni <info@tecnick.com>
 * @copyright   2011-2015 Nicola Asuni - Tecnick.com LTD
 * @license     http://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE.TXT)
 * @link        https://github.com/tecnickcom/tc-lib-pdf-encrypt
 */
class AESTest extends \PHPUnit_Framework_TestCase
{
    protected $obj;
    
    public function setUp()
    {
        //$this->markTestSkipped(); // skip this test
        $this->obj = new \Com\Tecnick\Pdf\Encrypt\Type\AES();
    }

    public function testEncryptException()
    {
        $this->setExpectedException('\Com\Tecnick\Pdf\Encrypt\Exception');
        $this->obj->encrypt('', '', 'raw');
    }

    public function testEncrypt()
    {
        $data = 'alpha beta';
        $key  = 'gamma';
        $enc_os = $this->obj->encrypt($data, $key, 'openssl');
        $enc_mc = $this->obj->encrypt($data, $key, 'mcrypt');
        $this->assertEquals(strlen($enc_os), strlen($enc_mc));
    }
}
