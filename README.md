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
const INT = types.INT;
const POINTER = types.POINTER;
const POINTER_TO_POINTER = types.POINTER_TO_POINTER;
const UTF8 = types.UTF8;

trace({
  module: 'libsqlite3.dylib',
  functions: [
    func('sqlite3_open', retval('result', INT), [
      argIn('filename', UTF8),
      argOut('ppDb', POINTER_TO_POINTER, whenResultIsZero),
    ]),
    func('sqlite3_prepare_v2', retval('result', INT), [
      argIn('db', POINTER),
      argIn('zSql', types.utf8({ length: trace.value.from('nByte') })),
      argIn('nByte', INT),
      argOut('ppStmt', POINTER_TO_POINTER, whenResultIsZero),
    ])
  ],
  callbacks: {
    onEvent(event) {
      console.log('onEvent! ' + JSON.stringify(event, null, 2));
    }
  }
});

function whenResultIsZero(resolve) {
  return resolve('result') === 0;
}
```
