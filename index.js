'use strict';

const IN = Symbol('in');
const OUT = Symbol('out');

module.exports = trace;

function trace(spec) {
  spec.functions.forEach(traceModuleFunction(spec.module, spec.callbacks.onEvent), spec);
}

trace.func = func;
trace.argIn = argIn;
trace.argOut = argOut;
trace.retval = retval;

trace.types = {
  INT: int(),
  POINTER: pointer(),
  POINTER_TO_POINTER: pointerToPointer(),
  UTF8: utf8(),

  int: int,
  pointer: pointer,
  utf8: utf8
};

trace.value = {
  from: from
};

function traceModuleFunction(module, emit) {
  return function (func) {
    const spec = this;

    const impl = Module.findExportByName(module, func.name);
    if (impl === null) {
      spec.callbacks.onError(new Error(`Failed to resolve ${module}!${func.name}`));
      return;
    }

    const funcName = func.name;
    const argSpecs = func.spec.args;
    const argSpecByName = argSpecs.reduce(function (result, spec, index) {
      result[spec.name] = [spec, index];
      return result;
    }, {});
    const retSpec = func.spec.ret;

    Interceptor.attach(impl, {
      onEnter(args) {
        const eventArgs = {};
        const event = { name: funcName, args: eventArgs };
        this.event = event;

        argSpecs.forEach(function (spec) { resolve(spec.name); });

        function resolve(name) {
          let value = eventArgs[name];
          if (value === undefined) {
            const pair = argSpecByName[name];
            if (pair === undefined)
              throw new Error('Unable to resolve "' + name + '"');
            const spec = pair[0];
            const index = pair[1];

            const rawValue = args[index];
            if (spec.direction === IN) {
              value = spec.get(rawValue, resolve);
            } else {
              value = function (resolve) {
                return spec.get(rawValue, resolve);
              };
            }
            eventArgs[name] = value;
          }
          return value;
        }
      },
      onLeave(retval) {
        const event = this.event;
        const eventArgs = event.args;

        Object.keys(eventArgs).forEach(function (name) {
          const value = eventArgs[name];
          if (value instanceof Function) {
            eventArgs[name] = value(resolve);
          }
        });

        if (retSpec !== null)
          resolve(retSpec.name);

        emit(event);

        function resolve(name) {
          if (retSpec !== null && name === retSpec.name) {
            let value = event.result;
            if (value === undefined) {
              value = retSpec.get(retval, resolve);
              event.result = value;
            }
            return value;
          } else {
            const value = eventArgs[name];
            if (value === undefined)
              throw new Error('Unable to resolve "' + name + '"');
            return value;
          }
        }
      }
    });
  };
}

function func(name, retSpec, argSpecs) {
  return {
    name: name,
    spec: {
      args: argSpecs,
      ret: retSpec
    }
  };
}

function argIn(name, type, condition) {
  return arg(IN, name, type, condition);
}

function argOut(name, type, condition) {
  return arg(OUT, name, type, condition);
}

function arg(direction, name, type, condition) {
  condition = condition || always;

  return {
    direction: direction,
    name: name,

    get(rawValue, resolve) {
      if (condition(resolve))
        return type.value(rawValue);
      else
        return null;
    }
  };
}

function always() {
  return true;
}

function retval(name, type, condition) {
  condition = condition || always;

  return {
    name: name,

    get(rawValue, resolve) {
      if (condition(resolve))
        return type.value(rawValue);
      else
        return null;
    }
  };
}

function int() {
  return {
    value(rawValue) {
      return rawValue.toInt32();
    }
  };
}

function pointer() {
  return {
    value(rawValue) {
      return rawValue;
    }
  };
}

function pointerToPointer() {
  return {
    value(rawValue) {
      if (rawValue.isNull())
        return null;
      return Memory.readPointer(rawValue);
    }
  };
}

function utf8() {
  return {
    value(rawValue) {
      return Memory.readUtf8String(rawValue);
    }
  };
}

function from(name) {
  return function (data) {
    return data.get(name);
  };
}
