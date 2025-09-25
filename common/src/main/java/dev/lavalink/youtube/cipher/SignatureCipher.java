package dev.lavalink.youtube.cipher;

import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptException;

/**
 * Describes one signature cipher
 */
public class SignatureCipher {
    private final String timestamp;
    private final String globalVars;
    private final String sigActions;
    private final String sigFunction;
    private final String nFunction;
    private final String rawScript;
    private final String sigFuncName;
    private final String nFuncName;

    protected SignatureCipher(String timestamp, String globalVars, String sigActions,
                              String sigFunction, String nFunction, String rawScript,
                              String sigFuncName, String nFuncName) {
        this.timestamp = timestamp;
        this.globalVars = globalVars;
        this.sigActions = sigActions;
        this.sigFunction = sigFunction;
        this.nFunction = nFunction;
        this.rawScript = rawScript;
        this.sigFuncName = sigFuncName;
        this.nFuncName = nFuncName;
    }

    public String apply(String signature, ScriptEngine scriptEngine) throws ScriptException, NoSuchMethodException {
        // ... (existing code for signature)
        // Change the method call to use the dynamically found function name
        return (String) scriptEngine.eval(sigFuncName + "(\"" + signature + "\");");
    }

    public String transform(String nParameter, ScriptEngine scriptEngine) throws ScriptException, NoSuchMethodException {
        // ... (existing code for n function)
        // Change the method call to use the dynamically found function name
        return (String) scriptEngine.eval(nFuncName + "(\"" + nParameter + "\");");
    }
}

  /**
   * @param text Text to apply the cipher on
   * @return The result of the cipher on the input text
   */
  

//  /**
//   * @param text Text to apply the cipher on
//   * @return The result of the cipher on the input text
//   */
//  public String apply(@NotNull String text) {
//    StringBuilder builder = new StringBuilder(text);
//
//    for (CipherOperation operation : operations) {
//      switch (operation.type) {
//        case SWAP:
//          int position = operation.parameter % text.length();
//          char temp = builder.charAt(0);
//          builder.setCharAt(0, builder.charAt(position));
//          builder.setCharAt(position, temp);
//          break;
//        case REVERSE:
//          builder.reverse();
//          break;
//        case SLICE:
//        case SPLICE:
//          builder.delete(0, operation.parameter);
//          break;
//        default:
//          throw new IllegalStateException("All branches should be covered");
//      }
//    }
//
//    return builder.toString();
//  }

  /**
   * @param text         Text to transform
   * @param scriptEngine JavaScript engine to execute function
   * @return The result of the n parameter transformation
   */


//  /**
//   * @param operation The operation to add to this cipher
//   */
//  public void addOperation(@NotNull CipherOperation operation) {
//    operations.add(operation);
//  }
//
//  /**
//   * @return True if the cipher contains no operations.
//   */
//  public boolean isEmpty() {
//    return operations.isEmpty();
//  }

