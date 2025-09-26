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
  private static final Logger log = LoggerFactory.getLogger(SignatureCipher.class);

  public final String timestamp;
  public final String globalVars;
  public final String sigActions;
  public final String sigFunction;
  public final String nFunction;
  public final String rawScript;

  public SignatureCipher(String timestamp, String globalVars, String sigActions, String sigFunction, String nFunction, String rawScript) {
        this.timestamp = timestamp;
        this.globalVars = globalVars;
        this.sigActions = sigActions;
        this.sigFunction = sigFunction;
        this.nFunction = nFunction;
        this.rawScript = rawScript;
    }

    /**
     * Apply the signature decipher (the "s" parameter).
     */
    public String apply(String signature, ScriptEngine engine) throws ScriptException, NoSuchMethodException {
        engine.eval(globalVars + ";" + sigActions + ";" + sigFunction);
        Invocable invocable = (Invocable) engine;
        Object raw = invocable.invokeFunction(extractFunctionName(sigFunction), signature);
        return normalizeReturn(raw);
    }

    /**
     * Transform the "n" parameter.
     */
    public String transform(String nParam, ScriptEngine engine) throws ScriptException, NoSuchMethodException {
        if (nFunction == null || nFunction.isEmpty()) {
            return nParam; // fallback: no transform
        }

        engine.eval(globalVars + ";" + sigActions + ";" + nFunction);
        Invocable invocable = (Invocable) engine;
        Object raw = invocable.invokeFunction(extractFunctionName(nFunction), nParam);
        return normalizeReturn(raw);
    }

    /**
     * Ensure we always return a String, even if the JS function returns a NativeArray.
     */
    private String normalizeReturn(Object raw) {
        if (raw == null) return null;

        if (raw instanceof String) {
            return (String) raw;
        } else if (raw instanceof NativeArray) {
            NativeArray arr = (NativeArray) raw;
            StringBuilder sb = new StringBuilder();
            for (Object o : arr) {
                if (o != null) sb.append(o.toString());
            }
            return sb.toString();
        } else {
            return raw.toString();
        }
    }

    /**
     * Extract function name from function declaration text.
     */
    private String extractFunctionName(String functionCode) {
        // Example: "function Abc(a){...}" -> "Abc"
        int idxStart = functionCode.indexOf("function");
        if (idxStart >= 0) {
            String after = functionCode.substring(idxStart + 8).trim();
            int parenIdx = after.indexOf("(");
            if (parenIdx > 0) {
                String name = after.substring(0, parenIdx).trim();
                if (!name.isEmpty()) {
                    return name;
                }
            }
        }
        // fallback: anonymous function, Lavalink usually assigns to var before use
        return null;
    }
}
