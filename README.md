# tc-lib-pdf-encrypt

> PDF encryption primitives for password protection and permission control.

[![Latest Stable Version](https://poser.pugx.org/tecnickcom/tc-lib-pdf-encrypt/version)](https://packagist.org/packages/tecnickcom/tc-lib-pdf-encrypt)
[![Build](https://github.com/tecnickcom/tc-lib-pdf-encrypt/actions/workflows/check.yml/badge.svg)](https://github.com/tecnickcom/tc-lib-pdf-encrypt/actions/workflows/check.yml)
[![Coverage](https://codecov.io/gh/tecnickcom/tc-lib-pdf-encrypt/graph/badge.svg?token=Pv1MNH3X3v)](https://codecov.io/gh/tecnickcom/tc-lib-pdf-encrypt)
[![License](https://poser.pugx.org/tecnickcom/tc-lib-pdf-encrypt/license)](https://packagist.org/packages/tecnickcom/tc-lib-pdf-encrypt)
[![Downloads](https://poser.pugx.org/tecnickcom/tc-lib-pdf-encrypt/downloads)](https://packagist.org/packages/tecnickcom/tc-lib-pdf-encrypt)

[![Donate via PayPal](https://img.shields.io/badge/donate-paypal-87ceeb.svg)](https://www.paypal.com/donate/?hosted_button_id=NZUEC5XS8MFBJ)

If this library helps secure your PDFs, please consider [supporting development via PayPal](https://www.paypal.com/donate/?hosted_button_id=NZUEC5XS8MFBJ).

---

## Overview

`tc-lib-pdf-encrypt` implements core encryption routines used by PDF generation and processing stacks, including password handling and permission flags.

The package encapsulates PDF security mechanics behind a focused API so consuming libraries can apply encryption policies without reimplementing cryptographic details. It is built for interoperability with standard PDF readers and for clear separation between document logic and security concerns.

| | |
|---|---|
| **Namespace** | `\Com\Tecnick\Pdf\Encrypt` |
| **Author** | Nicola Asuni <info@tecnick.com> |
| **License** | [GNU LGPL v3](https://www.gnu.org/copyleft/lesser.html) - see [LICENSE](LICENSE) |
| **API docs** | <https://tcpdf.org/docs/srcdoc/tc-lib-pdf-encrypt> |
| **Packagist** | <https://packagist.org/packages/tecnickcom/tc-lib-pdf-encrypt> |

---

## Features

### Encryption Support
- RC4 and AES variants for PDF object/string encryption
- User and owner password workflows
- Permission flag handling for document operations

### Integration
- Designed for direct use by PDF writer components
- Helpers for PDF date formatting and hex/string transforms
- Exception-driven error handling

---

## Requirements

- PHP 8.1 or later
- Extensions: `date`, `hash`, `openssl`, `pcre`
- Composer

---

## Installation

```bash
composer require tecnickcom/tc-lib-pdf-encrypt
```

---

## Quick Start

```php
<?php

require_once __DIR__ . '/vendor/autoload.php';

$encrypt = new \Com\Tecnick\Pdf\Encrypt\Encrypt();
$cipher = $encrypt->encryptString('secret payload', 12);

echo bin2hex($cipher);
```

### OpenSSL 3 Note

On OpenSSL 3 systems, legacy providers may be disabled by default. Enable legacy support when required by your runtime policy.

---

## Development

```bash
make deps
make help
make qa
```

---

## Packaging

```bash
make rpm
make deb
```

For system packages, bootstrap with:

```php
require_once '/usr/share/php/Com/Tecnick/Pdf/Encrypt/autoload.php';
```

---

## Contributing

Contributions are welcome. Please review [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and [SECURITY.md](SECURITY.md).

---

## Contact

Nicola Asuni - <info@tecnick.com>
