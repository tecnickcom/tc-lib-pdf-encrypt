<?php
/**
 * RCFourTest.php
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
 * RC4 encryption Test
 *
 * @since       2011-05-23
 * @category    Library
 * @package     PdfEncrypt
 * @author      Nicola Asuni <info@tecnick.com>
 * @copyright   2011-2015 Nicola Asuni - Tecnick.com LTD
 * @license     http://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE.TXT)
 * @link        https://github.com/tecnickcom/tc-lib-pdf-encrypt
 */
class RCFourTest extends \PHPUnit_Framework_TestCase
{
    protected $obj;
    
    public function setUp()
    {
        //$this->markTestSkipped(); // skip this test
        $this->obj = new \Com\Tecnick\Pdf\Encrypt\Type\RCFour();
    }

    public function testEncrypt()
    {
        $data = 'alpha';
        $key = 'beta';
        $enc_ext = $this->obj->encrypt($data, $key, 'mcrypt');
        $enc_raw = $this->obj->encrypt($data, $key, 'raw');
        $this->assertEquals($enc_ext, $enc_raw);
    }

    public function testEncryptModes()
    {
        $data = 'alpha';
        $key = 'beta';
        $enc_ext = $this->obj->encryptMcrypt($data, $key);
        $enc_raw = $this->obj->encryptRaw($data, $key);
        $this->assertEquals($enc_ext, $enc_raw);
    }
}
