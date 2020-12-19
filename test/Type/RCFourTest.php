<?php
/**
 * RCFourTest.php
 *
 * @since       2011-05-23
 * @category    Library
 * @package     PdfEncrypt
 * @author      Nicola Asuni <info@tecnick.com>
 * @copyright   2011-2017 Nicola Asuni - Tecnick.com LTD
 * @license     http://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE.TXT)
 * @link        https://github.com/tecnickcom/tc-lib-pdf-encrypt
 *
 * This file is part of tc-lib-pdf-encrypt software library.
 */

namespace Test;

use PHPUnit\Framework\TestCase;
use \Test\TestUtil;

/**
 * RC4 encryption Test
 *
 * @since       2011-05-23
 * @category    Library
 * @package     PdfEncrypt
 * @author      Nicola Asuni <info@tecnick.com>
 * @copyright   2011-2017 Nicola Asuni - Tecnick.com LTD
 * @license     http://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE.TXT)
 * @link        https://github.com/tecnickcom/tc-lib-pdf-encrypt
 */
class RCFourTest extends TestUtil
{
    protected function getTestObject()
    {
        return new \Com\Tecnick\Pdf\Encrypt\Type\RCFour();
    }

    public function testEncrypt40()
    {
        $testObj = $this->getTestObject();
        $data = 'alpha';
        $key = '12345'; // 5 bytes = 40 bit KEY

        $enc_a = $testObj->encrypt($data, $key, '');
        $enc_b = $testObj->encrypt($data, $key, 'RC4-40');
        $this->assertEquals($enc_a, $enc_b);
        
        $eobj = new \Com\Tecnick\Pdf\Encrypt\Type\RCFourFive();
        $enc_c = $eobj->encrypt($data, $key);
        $this->assertEquals($enc_a, $enc_c);
    }

    public function testEncrypt128()
    {
        $testObj = $this->getTestObject();
        $data = 'alpha';
        $key = '0123456789abcdef'; // 16 bytes = 128 bit KEY

        $enc_a = $testObj->encrypt($data, $key);
        $enc_b = $testObj->encrypt($data, $key, 'RC4');
        $this->assertEquals($enc_a, $enc_b);
        
        $eobj = new \Com\Tecnick\Pdf\Encrypt\Type\RCFourSixteen();
        $enc_c = $eobj->encrypt($data, $key);
        $this->assertEquals($enc_a, $enc_c);
    }

    public function testEncryptException()
    {
        $this->bcExpectException('\Com\Tecnick\Pdf\Encrypt\Exception');
        $testObj = $this->getTestObject();
        $testObj->encrypt('alpha', '12345', 'ERROR');
    }
}
