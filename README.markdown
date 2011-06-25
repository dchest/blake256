Package blake256
=====================

	import "github.com/dchest/blake256"

Package blake256 implements BLAKE-256 and BLAKE-224 hash functions (SHA-3
candidate).

Derived from reference implementation in C.

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
