# lua-skip32
a lua port of skip32 encryption (luajit required)

### usage
```lua
local skip32 = require "skip32"
local encrypted = skip32.encrypt("1234567890", "1234") -- encrypt
print(skip32.decrypt("1234567890", encrypted)) -- decrypt
```
remark: the return value type of encrypt is indicated by #2 argument type.
  
### test
```lua
local skip32 = require "skip32"
local testkey = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 }
local testdata = { 1, 2, 3, 4 }
local e = skip32.fpe_skip32(testkey, testdata, true)
print(unpack(e)) -- =>   240 199 178 180
print(unpack(skip32.encrypt(testkey, testdata))) -- =>   240 199 178 180
print(unpack(skip32.encrypt("\1\2\3\4\5\6\7\x08\x09\0", testdata))) -- =>   240 199 178 180
print(skip32.encrypt(testkey, "\1\2\3\4"):byte(1, 4)) -- =>   240 199 178 180
print(skip32.encrypt(testkey, 0x04030201)) -- => -1263351824 (0xB4B2C7F0)
local d = skip32.fpe_skip32(testkey, e, false)
print(unpack(d)) -- =>   1   2   3   4
```

### output
```
240	199	178	180
240	199	178	180
240	199	178	180
240	199	178	180
-1263351824
1	2	3	4
```
