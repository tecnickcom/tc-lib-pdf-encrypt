<?php

    // ENCRYPTION METHODS ----------------------------------




    /**
     * Compute UE value (used for encryption)
     * @return string UE value
     * @protected
     * @since 5.9.006 (2010-10-19)
     * @author Nicola Asuni
     */
    protected function _UEvalue() {
        $hashkey = hash('sha256', $this->encryptdata['user_password'].$this->encryptdata['UKS'], true);
        return TCPDF_STATIC::_AESnopad($hashkey, $this->encryptdata['key']);
    }

    /**
     * Compute OE value (used for encryption)
     * @return string OE value
     * @protected
     * @since 5.9.006 (2010-10-19)
     * @author Nicola Asuni
     */
    protected function _OEvalue() {
        $hashkey = hash('sha256', $this->encryptdata['owner_password'].$this->encryptdata['OKS'].$this->encryptdata['U'], true);
        return TCPDF_STATIC::_AESnopad($hashkey, $this->encryptdata['key']);
    }



    /**
     * Compute U value (used for encryption)
     * @return string U value
     * @protected
     * @since 2.0.000 (2008-01-02)
     * @author Nicola Asuni
     */
    protected function _Uvalue() {
        if ($this->encryptdata['mode'] == 0) { // RC4-40
            return TCPDF_STATIC::_RC4($this->encryptdata['key'], TCPDF_STATIC::$enc_padding, $this->last_enc_key, $this->last_enc_key_c);
        } elseif ($this->encryptdata['mode'] < 3) { // RC4-128, AES-128
            $tmp = TCPDF_STATIC::_md5_16(TCPDF_STATIC::$enc_padding.$this->encryptdata['fileid']);
            $enc = TCPDF_STATIC::_RC4($this->encryptdata['key'], $tmp, $this->last_enc_key, $this->last_enc_key_c);
            $len = strlen($tmp);
            for ($i = 1; $i <= 19; ++$i) {
                $ek = '';
                for ($j = 0; $j < $len; ++$j) {
                    $ek .= chr(ord($this->encryptdata['key'][$j]) ^ $i);
                }
                $enc = TCPDF_STATIC::_RC4($ek, $enc, $this->last_enc_key, $this->last_enc_key_c);
            }
            $enc .= str_repeat("\x00", 16);
            return substr($enc, 0, 32);
        } elseif ($this->encryptdata['mode'] == 3) { // AES-256
            $seed = TCPDF_STATIC::_md5_16(TCPDF_STATIC::getRandomSeed());
            // User Validation Salt
            $this->encryptdata['UVS'] = substr($seed, 0, 8);
            // User Key Salt
            $this->encryptdata['UKS'] = substr($seed, 8, 16);
            return hash('sha256', $this->encryptdata['user_password'].$this->encryptdata['UVS'], true).$this->encryptdata['UVS'].$this->encryptdata['UKS'];
        }
    }

    /**
     * Compute O value (used for encryption)
     * @return string O value
     * @protected
     * @since 2.0.000 (2008-01-02)
     * @author Nicola Asuni
     */
    protected function _Ovalue() {
        if ($this->encryptdata['mode'] < 3) { // RC4-40, RC4-128, AES-128
            $tmp = TCPDF_STATIC::_md5_16($this->encryptdata['owner_password']);
            if ($this->encryptdata['mode'] > 0) {
                for ($i = 0; $i < 50; ++$i) {
                    $tmp = TCPDF_STATIC::_md5_16($tmp);
                }
            }
            $owner_key = substr($tmp, 0, ($this->encryptdata['Length'] / 8));
            $enc = TCPDF_STATIC::_RC4($owner_key, $this->encryptdata['user_password'], $this->last_enc_key, $this->last_enc_key_c);
            if ($this->encryptdata['mode'] > 0) {
                $len = strlen($owner_key);
                for ($i = 1; $i <= 19; ++$i) {
                    $ek = '';
                    for ($j = 0; $j < $len; ++$j) {
                        $ek .= chr(ord($owner_key[$j]) ^ $i);
                    }
                    $enc = TCPDF_STATIC::_RC4($ek, $enc, $this->last_enc_key, $this->last_enc_key_c);
                }
            }
            return $enc;
        } elseif ($this->encryptdata['mode'] == 3) { // AES-256
            $seed = TCPDF_STATIC::_md5_16(TCPDF_STATIC::getRandomSeed());
            // Owner Validation Salt
            $this->encryptdata['OVS'] = substr($seed, 0, 8);
            // Owner Key Salt
            $this->encryptdata['OKS'] = substr($seed, 8, 16);
            return hash('sha256', $this->encryptdata['owner_password'].$this->encryptdata['OVS'].$this->encryptdata['U'], true).$this->encryptdata['OVS'].$this->encryptdata['OKS'];
        }
    }





    /**
     * Convert password for AES-256 encryption mode
     * @param $password (string) password
     * @return string password
     * @protected
     * @since 5.9.006 (2010-10-19)
     * @author Nicola Asuni
     */
    protected function _fixAES256Password($password) {
        $psw = ''; // password to be returned
        $psw_array = TCPDF_FONTS::utf8Bidi(TCPDF_FONTS::UTF8StringToArray($password, $this->isunicode, $this->CurrentFont), $password, $this->rtl, $this->isunicode, $this->CurrentFont);
        foreach ($psw_array as $c) {
            $psw .= TCPDF_FONTS::unichr($c, $this->isunicode);
        }
        return substr($psw, 0, 127);
    }

    /**
     * Compute encryption key
     * @protected
     * @since 2.0.000 (2008-01-02)
     * @author Nicola Asuni
     */
    protected function _generateencryptionkey() {
        $keybytelen = ($this->encryptdata['Length'] / 8);
        if (!$this->encryptdata['pubkey']) { // standard mode
            if ($this->encryptdata['mode'] == 3) { // AES-256
                // generate 256 bit random key
                $this->encryptdata['key'] = substr(hash('sha256', TCPDF_STATIC::getRandomSeed(), true), 0, $keybytelen);
                // truncate passwords
                $this->encryptdata['user_password'] = $this->_fixAES256Password($this->encryptdata['user_password']);
                $this->encryptdata['owner_password'] = $this->_fixAES256Password($this->encryptdata['owner_password']);
                // Compute U value
                $this->encryptdata['U'] = $this->_Uvalue();
                // Compute UE value
                $this->encryptdata['UE'] = $this->_UEvalue();
                // Compute O value
                $this->encryptdata['O'] = $this->_Ovalue();
                // Compute OE value
                $this->encryptdata['OE'] = $this->_OEvalue();
                // Compute P value
                $this->encryptdata['P'] = $this->encryptdata['protection'];
                // Computing the encryption dictionary's Perms (permissions) value
                $perms = TCPDF_STATIC::getEncPermissionsString($this->encryptdata['protection']); // bytes 0-3
                $perms .= chr(255).chr(255).chr(255).chr(255); // bytes 4-7
                if (isset($this->encryptdata['CF']['EncryptMetadata']) AND (!$this->encryptdata['CF']['EncryptMetadata'])) { // byte 8
                    $perms .= 'F';
                } else {
                    $perms .= 'T';
                }
                $perms .= 'adb'; // bytes 9-11
                $perms .= 'nick'; // bytes 12-15
                $this->encryptdata['perms'] = TCPDF_STATIC::_AESnopad($this->encryptdata['key'], $perms);
            } else { // RC4-40, RC4-128, AES-128
                // Pad passwords
                $this->encryptdata['user_password'] = substr($this->encryptdata['user_password'].TCPDF_STATIC::$enc_padding, 0, 32);
                $this->encryptdata['owner_password'] = substr($this->encryptdata['owner_password'].TCPDF_STATIC::$enc_padding, 0, 32);
                // Compute O value
                $this->encryptdata['O'] = $this->_Ovalue();
                // get default permissions (reverse byte order)
                $permissions = TCPDF_STATIC::getEncPermissionsString($this->encryptdata['protection']);
                // Compute encryption key
                $tmp = TCPDF_STATIC::_md5_16($this->encryptdata['user_password'].$this->encryptdata['O'].$permissions.$this->encryptdata['fileid']);
                if ($this->encryptdata['mode'] > 0) {
                    for ($i = 0; $i < 50; ++$i) {
                        $tmp = TCPDF_STATIC::_md5_16(substr($tmp, 0, $keybytelen));
                    }
                }
                $this->encryptdata['key'] = substr($tmp, 0, $keybytelen);
                // Compute U value
                $this->encryptdata['U'] = $this->_Uvalue();
                // Compute P value
                $this->encryptdata['P'] = $this->encryptdata['protection'];
            }
        } else { // Public-Key mode
            // random 20-byte seed
            $seed = sha1(TCPDF_STATIC::getRandomSeed(), true);
            $recipient_bytes = '';
            foreach ($this->encryptdata['pubkeys'] as $pubkey) {
                // for each public certificate
                if (isset($pubkey['p'])) {
                    $pkprotection = TCPDF_STATIC::getUserPermissionCode($pubkey['p'], $this->encryptdata['mode']);
                } else {
                    $pkprotection = $this->encryptdata['protection'];
                }
                // get default permissions (reverse byte order)
                $pkpermissions = TCPDF_STATIC::getEncPermissionsString($pkprotection);
                // envelope data
                $envelope = $seed.$pkpermissions;
                // write the envelope data to a temporary file
                $tempkeyfile = TCPDF_STATIC::getObjFilename('key', $this->file_id);
                $f = TCPDF_STATIC::fopenLocal($tempkeyfile, 'wb');
                if (!$f) {
                    $this->Error('Unable to create temporary key file: '.$tempkeyfile);
                }
                $envelope_length = strlen($envelope);
                fwrite($f, $envelope, $envelope_length);
                fclose($f);
                $tempencfile = TCPDF_STATIC::getObjFilename('enc', $this->file_id);
                if (!openssl_pkcs7_encrypt($tempkeyfile, $tempencfile, $pubkey['c'], array(), PKCS7_BINARY | PKCS7_DETACHED)) {
                    $this->Error('Unable to encrypt the file: '.$tempkeyfile);
                }
                // read encryption signature
                $signature = file_get_contents($tempencfile, false, null, $envelope_length);
                // extract signature
                $signature = substr($signature, strpos($signature, 'Content-Disposition'));
                $tmparr = explode("\n\n", $signature);
                $signature = trim($tmparr[1]);
                unset($tmparr);
                // decode signature
                $signature = base64_decode($signature);
                // convert signature to hex
                $hexsignature = current(unpack('H*', $signature));
                // store signature on recipients array
                $this->encryptdata['Recipients'][] = $hexsignature;
                // The bytes of each item in the Recipients array of PKCS#7 objects in the order in which they appear in the array
                $recipient_bytes .= $signature;
            }
            // calculate encryption key
            if ($this->encryptdata['mode'] == 3) { // AES-256
                $this->encryptdata['key'] = substr(hash('sha256', $seed.$recipient_bytes, true), 0, $keybytelen);
            } else { // RC4-40, RC4-128, AES-128
                $this->encryptdata['key'] = substr(sha1($seed.$recipient_bytes, true), 0, $keybytelen);
            }
        }
    }




    /**
     * Put encryption on PDF document.
     * @protected
     * @author Nicola Asuni
     * @since 2.0.000 (2008-01-02)
     */
    protected function _putencryption() {
        if (!$this->encrypted) {
            return;
        }
        $this->encryptdata['objid'] = $this->_newobj();
        $out = '<<';
        if (!isset($this->encryptdata['Filter']) OR empty($this->encryptdata['Filter'])) {
            $this->encryptdata['Filter'] = 'Standard';
        }
        $out .= ' /Filter /'.$this->encryptdata['Filter'];
        if (isset($this->encryptdata['SubFilter']) AND !empty($this->encryptdata['SubFilter'])) {
            $out .= ' /SubFilter /'.$this->encryptdata['SubFilter'];
        }
        if (!isset($this->encryptdata['V']) OR empty($this->encryptdata['V'])) {
            $this->encryptdata['V'] = 1;
        }
        // V is a code specifying the algorithm to be used in encrypting and decrypting the document
        $out .= ' /V '.$this->encryptdata['V'];
        if (isset($this->encryptdata['Length']) AND !empty($this->encryptdata['Length'])) {
            // The length of the encryption key, in bits. The value shall be a multiple of 8, in the range 40 to 256
            $out .= ' /Length '.$this->encryptdata['Length'];
        } else {
            $out .= ' /Length 40';
        }
        if ($this->encryptdata['V'] >= 4) {
            if (!isset($this->encryptdata['StmF']) OR empty($this->encryptdata['StmF'])) {
                $this->encryptdata['StmF'] = 'Identity';
            }
            if (!isset($this->encryptdata['StrF']) OR empty($this->encryptdata['StrF'])) {
                // The name of the crypt filter that shall be used when decrypting all strings in the document.
                $this->encryptdata['StrF'] = 'Identity';
            }
            // A dictionary whose keys shall be crypt filter names and whose values shall be the corresponding crypt filter dictionaries.
            if (isset($this->encryptdata['CF']) AND !empty($this->encryptdata['CF'])) {
                $out .= ' /CF <<';
                $out .= ' /'.$this->encryptdata['StmF'].' <<';
                $out .= ' /Type /CryptFilter';
                if (isset($this->encryptdata['CF']['CFM']) AND !empty($this->encryptdata['CF']['CFM'])) {
                    // The method used
                    $out .= ' /CFM /'.$this->encryptdata['CF']['CFM'];
                    if ($this->encryptdata['pubkey']) {
                        $out .= ' /Recipients [';
                        foreach ($this->encryptdata['Recipients'] as $rec) {
                            $out .= ' <'.$rec.'>';
                        }
                        $out .= ' ]';
                        if (isset($this->encryptdata['CF']['EncryptMetadata']) AND (!$this->encryptdata['CF']['EncryptMetadata'])) {
                            $out .= ' /EncryptMetadata false';
                        } else {
                            $out .= ' /EncryptMetadata true';
                        }
                    }
                } else {
                    $out .= ' /CFM /None';
                }
                if (isset($this->encryptdata['CF']['AuthEvent']) AND !empty($this->encryptdata['CF']['AuthEvent'])) {
                    // The event to be used to trigger the authorization that is required to access encryption keys used by this filter.
                    $out .= ' /AuthEvent /'.$this->encryptdata['CF']['AuthEvent'];
                } else {
                    $out .= ' /AuthEvent /DocOpen';
                }
                if (isset($this->encryptdata['CF']['Length']) AND !empty($this->encryptdata['CF']['Length'])) {
                    // The bit length of the encryption key.
                    $out .= ' /Length '.$this->encryptdata['CF']['Length'];
                }
                $out .= ' >> >>';
            }
            // The name of the crypt filter that shall be used by default when decrypting streams.
            $out .= ' /StmF /'.$this->encryptdata['StmF'];
            // The name of the crypt filter that shall be used when decrypting all strings in the document.
            $out .= ' /StrF /'.$this->encryptdata['StrF'];
            if (isset($this->encryptdata['EFF']) AND !empty($this->encryptdata['EFF'])) {
                // The name of the crypt filter that shall be used when encrypting embedded file streams that do not have their own crypt filter specifier.
                $out .= ' /EFF /'.$this->encryptdata[''];
            }
        }
        // Additional encryption dictionary entries for the standard security handler
        if ($this->encryptdata['pubkey']) {
            if (($this->encryptdata['V'] < 4) AND isset($this->encryptdata['Recipients']) AND !empty($this->encryptdata['Recipients'])) {
                $out .= ' /Recipients [';
                foreach ($this->encryptdata['Recipients'] as $rec) {
                    $out .= ' <'.$rec.'>';
                }
                $out .= ' ]';
            }
        } else {
            $out .= ' /R';
            if ($this->encryptdata['V'] == 5) { // AES-256
                $out .= ' 5';
                $out .= ' /OE ('.TCPDF_STATIC::_escape($this->encryptdata['OE']).')';
                $out .= ' /UE ('.TCPDF_STATIC::_escape($this->encryptdata['UE']).')';
                $out .= ' /Perms ('.TCPDF_STATIC::_escape($this->encryptdata['perms']).')';
            } elseif ($this->encryptdata['V'] == 4) { // AES-128
                $out .= ' 4';
            } elseif ($this->encryptdata['V'] < 2) { // RC-40
                $out .= ' 2';
            } else { // RC-128
                $out .= ' 3';
            }
            $out .= ' /O ('.TCPDF_STATIC::_escape($this->encryptdata['O']).')';
            $out .= ' /U ('.TCPDF_STATIC::_escape($this->encryptdata['U']).')';
            $out .= ' /P '.$this->encryptdata['P'];
            if (isset($this->encryptdata['EncryptMetadata']) AND (!$this->encryptdata['EncryptMetadata'])) {
                $out .= ' /EncryptMetadata false';
            } else {
                $out .= ' /EncryptMetadata true';
            }
        }
        $out .= ' >>';
        $out .= "\n".'endobj';
        $this->_out($out);
    }








