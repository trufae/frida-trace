'use strict';

const IN = Symbol('in');
const OUT = Symbol('out');
const IN_OUT = Symbol('in-out');

module.exports = trace;

function trace(spec) {
  spec.functions.forEach(traceModuleFunction(spec.module, spec.callbacks.onEvent), spec);
}

trace.func = func;
trace.argIn = argIn;
trace.argOut = argOut;
trace.argInOut = argInOut;
trace.retval = retval;

trace.bind = bind;
trace.when = when;

trace.types = {
  BYTE: byte(),
  SHORT: short(),
  INT: int(),
  POINTER: pointer(),
  BYTE_ARRAY: byteArray(),
  UTF8: utf8(),
  UTF16: utf16(),

  byte: byte,
  short: short,
  int: int,
  pointer: pointer,
  byteArray: byteArray,
  utf8: utf8,
  utf16: utf16,
};

function traceModuleFunction(module, emit) {
  return function (func) {
    const name = func.name;
    const spec = this;

    const impl = Module.findExportByName(module, name);
    if (impl === null) {
      spec.callbacks.onError(new Error(`Failed to resolve ${module}!${name}`));
      return;
    }

    const inputActions = [];
    const outputActions = [];
    if (!computeActions(func, inputActions, outputActions)) {
      spec.callbacks.onError(new Error(`Oops. It seems ${module}!${name} has circular dependencies.`));
      return;
    }

    const numArgs = func.args.length;
    const numInputActions = inputActions.length;
    const numOutputActions = outputActions.length;

    Interceptor.attach(impl, {
      onEnter(args) {
        const values = [];
        for (let i = 0; i !== numArgs; i++)
          values.push(args[i]);

        const event = new Event(name);
        for (let i = 0; i !== numInputActions; i++) {
          const item = inputActions[i];
          const action = item[0];
          const params = item[1];
          action(values, event, params);
        }

        this.values = values;
        this.event = event;
      },
      onLeave(retval) {
        const values = this.values;
        const event = this.event;

        values.push(retval);

        for (let i = 0; i !== numOutputActions; i++) {
          const item = outputActions[i];
          const action = item[0];
          const params = item[1];
          action(values, event, params);
        }

        emit(event);
      }
    });
  };
}

function computeActions(func, inputActions, outputActions) {
  const args = func.args.slice();
  if (func.ret !== null)
    args.push(func.ret);

  const satisfied = new Set();
  let previousSatisfiedSize;

  do {
    previousSatisfiedSize = satisfied.size;

    args.forEach(function (arg, index) {
      if (satisfied.has(arg.name))
        return;
      const remaining = arg.requires.filter(dep => !satisfied.has(dep));
      if (remaining.length === 0) {
        inputActions.push(computeAction(arg, index));
        satisfied.add(arg.name);
      }
    });
  } while (satisfied.size !== previousSatisfiedSize);

  satisfied.add('$out');

  do {
    previousSatisfiedSize = satisfied.size;

    args.forEach(function (arg, index) {
      if (satisfied.has(arg.name))
        return;
      const remaining = arg.requires.filter(dep => !satisfied.has(dep));
      if (remaining.length === 0) {
        outputActions.push(computeAction(arg, index));
        satisfied.add(arg.name);
      }
    });
  } while (satisfied.size !== previousSatisfiedSize);

  return !args.some(arg => !satisfied.has(arg.name));
}

function computeAction(arg, index) {
  const name = arg.name;
  const type = arg.type;
  const condition = arg.condition;

  const hasDependentType = type instanceof Array;
  const hasCondition = condition !== null;

  if (!hasDependentType && !hasCondition) {
    return [readValue, [index, name, type.parse]];
  } else if (!hasDependentType && hasCondition) {
    return [readValueConditionally, [index, name, type.parse, condition]];
  } else if (hasDependentType && !hasCondition) {
    return [readValueWithDependentType, [index, name, type[0].parse, type[1]]];
  } else if (hasDependentType && hasCondition) {
    return [readValueWithDependentTypeConditionally, [index, name, type[0].parse, type[1], condition]];
  }
}

function readValue(values, event, params) {
  const index = params[0];
  const name = params[1];
  const parse = params[2];

  event.set(name, parse(values[index]));
}

function readValueConditionally(values, event, params) {
  const index = params[0];
  const name = params[1];
  const parse = params[2];
  const condition = params[3];

  if (condition.predicate(event.get(condition.value)))
    event.set(name, parse(values[index]));
}

function readValueWithDependentType(values, event, params) {
  const index = params[0];
  const name = params[1];
  const parse = params[2];
  const binding = params[3];

  const typeParameters = {};
  typeParameters[binding.property] = event.get(binding.value);
  event.set(name, parse(values[index], typeParameters));
}

function readValueWithDependentTypeConditionally(values, event, params) {
  const index = params[0];
  const name = params[1];
  const parse = params[2];
  const binding = params[3];
  const condition = params[4];

  if (condition.predicate(event.get(condition.value))) {
    const typeParameters = {};
    typeParameters[binding.property] = event.get(binding.value);
    event.set(name, parse(values[index], typeParameters));
  }
}

function func(name, ret, args) {
  return {
    name: name,
    ret: ret,
    args: args
  };
}

function argIn(name, type, condition) {
  return arg(IN, name, type, condition);
}

function argOut(name, type, condition) {
  return arg(OUT, name, type, condition);
}

function argInOut(name, type, condition) {
  return arg(IN_OUT, name, type, condition);
}

function arg(direction, name, type, condition) {
  condition = condition || null;

  return {
    direction: direction,
    name: name,
    type: type,
    condition: condition,
    requires: dependencies(direction, type, condition)
  };
}

function retval(type, condition) {
  return argOut('result', type, condition);
}

function bind(property, value) {
  return {
    property: property,
    value: value
  };
}

function when(value, predicate) {
  return {
    value: value,
    predicate: predicate
  };
}

function dependencies(direction, type, condition) {
  const result = [];

  if (direction === OUT)
    result.push('$out');

  if (type instanceof Array)
    result.push(type[1].value);

  if (condition !== null)
    result.push(condition.value);

  return result;
}

function byte() {
  return {
    parse(rawValue) {
      return rawValue.toInt32() & 0xff;
    },
    read(ptr) {
      return Memory.readU8(ptr);
    }
  };
}

function short() {
  return {
    parse(rawValue) {
      return rawValue.toInt32() & 0xffff;
    },
    read(ptr) {
      return Memory.readShort(ptr);
    }
  };
}


function int() {
  return {
    parse(rawValue) {
      return rawValue.toInt32();
    },
    read(ptr) {
      return Memory.readInt(ptr);
    }
  };
}

function pointer(pointee) {
  return {
    parse(rawValue, parameters) {
      if (pointee) {
        if (rawValue.isNull())
          return null;
        else
          return pointee.read(rawValue, parameters);
      } else {
        return rawValue;
      }
    },
    read(ptr) {
      return Memory.readPointer(ptr);
    }
  };
}

function byteArray() {
  return pointer({
    read(ptr, parameters) {
      return Memory.readByteArray(ptr, parameters.length);
    }
  });
}

function utf8() {
  return pointer({
    read(ptr, parameters) {
      const length = (parameters === undefined) ? -1 : parameters.length;
      return Memory.readUtf8String(ptr, length);
    }
  });
}

function utf16() {
  return pointer({
    read(ptr, parameters) {
      const length = (parameters === undefined) ? -1 : parameters.length;
      return Memory.readUtf16String(ptr, length);
    }
  });
}

class Event {
  constructor(name) {
    this.name = name;
    this.args = {};
  }

  get(key) {
    return (key === 'result') ? this.result : this.args[key];
  }

  set(key, value) {
    if (key === 'result')
      this.result = value;
    else
      this.args[key] = value;
  }
}
