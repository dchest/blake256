Package blake256
=====================

	import "github.com/dchest/blake256"

Package blake256 implements BLAKE-256 and BLAKE-224 hash functions (SHA-3
candidate).

Derived from blake256_light.c: light portable C implementation of BLAKE-256
(http://www.131002.net/blake/#sw)

Public domain.


Constants
---------

``` go
const BlockSize = 64
```
The block size of the hash algorithm in bytes.


Functions
---------

### func New

	func New() hash.Hash

New returns a new hash.Hash computing the BLAKE-256 checksum.

### func New224

	func New224() hash.Hash

New224 returns a new hash.Hash computing the BLAKE-224 checksum.
