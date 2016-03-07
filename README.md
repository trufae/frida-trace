# frida-trace

Trace APIs declaratively through [Frida](http://frida.re).

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
