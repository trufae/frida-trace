# frida-trace

Trace APIs declaratively through [Frida](http://frida.re).

Also includes a CLI tool for parsing header files and generating JSON:

```sh
$ ./bin/parse-header.js /usr/include/sqlite3.h | jq '.'
{
  "sqlite3_open": [
    "Int",
    [
      [
        "filename",
        [
          [
            "Pointer",
            []
          ],
          [
            "Char_S",
            [
              "const"
            ]
          ]
        ]
      ],
      [
        "ppDb",
        [
          [
            "Pointer",
            []
          ],
          [
            "Pointer",
            []
          ],
          [
            "Typedef",
            []
          ]
        ]
      ]
    ]
  ],
  "sqlite3_open16": [
    "Int",
    [
      [
        "filename",
        [
          [
            "Pointer",
            []
          ],
          [
            "Void",
            [
              "const"
            ]
          ]
        ]
      ],
      [
        "ppDb",
        [
          [
            "Pointer",
            []
          ],
          [
            "Pointer",
            []
          ],
          [
            "Typedef",
            []
          ]
        ]
      ]
    ]
  ],
  ...
}
```

You may have to patch `node_modules/libclang/lib/dynamic_clang.js` and modify
line 946 to specify the full path to libclang.dylib, e.g.:
`/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/libclang`

## Example

```js
const trace = require('@viaforensics/frida-trace');

const func = trace.func;
const argIn = trace.argIn;
const argOut = trace.argOut;
const retval = trace.retval;

const types = trace.types;
const pointer = types.pointer;
const INT = types.INT;
const POINTER = types.POINTER;
const UTF8 = types.UTF8;

trace({
  module: 'libsqlite3.dylib',
  functions: [
    func('sqlite3_open', retval(INT), [
      argIn('filename', UTF8),
      argOut('ppDb', pointer(POINTER), when('result', isZero)),
    ]),
    func('sqlite3_prepare_v2', retval(INT), [
      argIn('db', POINTER),
      argIn('zSql', [UTF8, bind('length', 'nByte')]),
      argIn('nByte', INT),
      argOut('ppStmt', pointer(POINTER), when('result', isZero)),
    ])
  ],
  callbacks: {
    onEvent(event) {
      console.log('onEvent! ' + JSON.stringify(event, null, 2));
    },
    onError(e) {
      console.error(e);
    }
  }
});

function isZero(value) {
  return value === 0;
}
```
