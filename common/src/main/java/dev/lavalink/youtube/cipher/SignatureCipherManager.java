package dev.lavalink.youtube.cipher;

import com.sedmelluq.discord.lavaplayer.tools.DataFormatTools;
import com.sedmelluq.discord.lavaplayer.tools.ExceptionTools;
import com.sedmelluq.discord.lavaplayer.tools.io.HttpClientTools;
import com.sedmelluq.discord.lavaplayer.tools.io.HttpInterface;
import dev.lavalink.youtube.YoutubeSource;
import dev.lavalink.youtube.cipher.ScriptExtractionException.ExtractionFailureType;
import dev.lavalink.youtube.track.format.StreamFormat;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.util.EntityUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.mozilla.javascript.engine.RhinoScriptEngineFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.script.ScriptEngine;
import javax.script.ScriptException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import static com.sedmelluq.discord.lavaplayer.tools.ExceptionTools.throwWithDebugInfo;

/**
 * Handles parsing and caching of signature ciphers
 */
@SuppressWarnings({"RegExpRedundantEscape", "RegExpUnnecessaryNonCapturingGroup"})
public class SignatureCipherManager {
  private static final Logger log = LoggerFactory.getLogger(SignatureCipherManager.class);

  private static final String VARIABLE_PART = "[a-zA-Z_\\$][a-zA-Z_0-9\\$]*";
  private static final String VARIABLE_PART_OBJECT_DECLARATION = "[\"']?[a-zA-Z_\\$][a-zA-Z_0-9\\$]*[\"']?";

  private static final Pattern TIMESTAMP_PATTERN = Pattern.compile("(signatureTimestamp|sts):(\\d+)");

  private static final Pattern GLOBAL_VARS_PATTERN = Pattern.compile(
      "('use\\s*strict';)?" +
          "(?<code>var\\s*(?<varname>[a-zA-Z0-9_$]+)\\s*=\\s*" +
          "(?<value>(?:\"[^\"\\\\]*(?:\\\\.[^\"\\\\]*)*\"|'[^'\\\\]*(?:\\\\.[^'\\\\]*)*')" +
          "\\.split\\((?:\"[^\"\\\\]*(?:\\\\.[^\"\\\\]*)*\"|'[^'\\\\]*(?:\\\\.[^'\\\\]*)*')\\)" +
          "|\\[(?:(?:\"[^\"\\\\]*(?:\\\\.[^\"\\\\]*)*\"|'[^'\\\\]*(?:\\\\.[^'\\\\]*)*')\\s*,?\\s*)*\\]" +
          "|\"[^\"]*\"\\.split\\(\"[^\"]*\"\\)))"
  );

  private static final Pattern ACTIONS_PATTERN = Pattern.compile(
      "var\\s+([$A-Za-z0-9_]+)\\s*=\\s*\\{" +
          "\\s*" + VARIABLE_PART_OBJECT_DECLARATION + "\\s*:\\s*function\\s*\\([^)]*\\)\\s*\\{[^{}]*(?:\\{[^{}]*}[^{}]*)*}\\s*," +
          "\\s*" + VARIABLE_PART_OBJECT_DECLARATION + "\\s*:\\s*function\\s*\\([^)]*\\)\\s*\\{[^{}]*(?:\\{[^{}]*}[^{}]*)*}\\s*," +
          "\\s*" + VARIABLE_PART_OBJECT_DECLARATION + "\\s*:\\s*function\\s*\\([^)]*\\)\\s*\\{[^{}]*(?:\\{[^{}]*}[^{}]*)*}\\s*};");

private static final Pattern SIG_FUNCTION_PATTERN = Pattern.compile(
    "(" +
        // function foo(a){ a=a.split(""); ... return a.join(""); }
        "function\\s+" + VARIABLE_PART + "\\s*\\(\\s*(" + VARIABLE_PART + ")\\s*\\)\\s*\\{[\\s\\S]{0,800}?\\.join\\(\"\"\\)[\\s\\S]{0,800}?\\}" +
        "|" +
        // foo=function(a){ a=a.split(""); ... return a.join(""); }
        VARIABLE_PART + "\\s*=\\s*function\\s*\\(\\s*(" + VARIABLE_PART + ")\\s*\\)\\s*\\{[\\s\\S]{0,800}?\\.join\\(\"\"\\)[\\s\\S]{0,800}?\\}" +
    ")",
    Pattern.DOTALL
);

// Legacy strict n-function pattern (kept for older scripts)
private static final Pattern N_FUNCTION_PATTERN = Pattern.compile(
    "function\\(\\s*(" + VARIABLE_PART + ")\\s*\\)\\s*\\{" +
        "var\\s*(" + VARIABLE_PART + ")=\\1\\[" + VARIABLE_PART + "\\[\\d+\\]\\]\\(" + VARIABLE_PART + "\\[\\d+\\]\\)" +
        ".*?catch\\(\\s*(\\w+)\\s*\\)\\s*\\{" +
        "\\s*return.*?\\+\\s*\\1\\s*}" +
        "\\s*return\\s*\\2\\[" + VARIABLE_PART + "\\[\\d+\\]\\]\\(" + VARIABLE_PART + "\\[\\d+\\]\\)};",
    Pattern.DOTALL
);

// Very-permissive fallback: match ANY single-arg function or assignment that either:
//  - contains both .split(...) and .join(...)
//  - OR calls a short helper with that param and then returns it
// This will capture most modern minified n() implementations.
private static final Pattern N_FUNCTION_FALLBACK = Pattern.compile(
    "(" +
      // named function: function fname(a) { ... split(...) ... join(...) ... }
      "function\\s*(?:[A-Za-z0-9_$]{0,14})\\s*\\(\\s*(" + VARIABLE_PART + ")\\s*\\)\\s*\\{[\\s\\S]{0,2000}?split\\s*\\(\\s*['\"]?['\"]?\\s*\\)[\\s\\S]{0,2000}?join\\s*\\(\\s*['\"]?['\"]?\\s*\\)[\\s\\S]{0,2000}?\\}" +
      "|" +
      // assignment: name=function(a){ ... split/join ... }
      VARIABLE_PART + "\\s*=\\s*function\\s*\\(\\s*(" + VARIABLE_PART + ")\\s*\\)\\s*\\{[\\s\\S]{0,2200}?split\\s*\\(\\s*['\"]?['\"]?\\s*\\)[\\s\\S]{0,2200}?join\\s*\\(\\s*['\"]?['\"]?\\s*\\)[\\s\\S]{0,2200}?\\}" +
      "|" +
      // helper-call style: function foo(a){ a = helper(a,NUM); return a; }
      "function\\s*(?:[A-Za-z0-9_$]{0,14})\\s*\\(\\s*(" + VARIABLE_PART + ")\\s*\\)\\s*\\{[\\s\\S]{0,2000}?(?:[A-Za-z0-9_$]{1,8}\\s*\\(\\s*\\2\\s*,\\s*\\d+\\s*\\))[\\s\\S]{0,2000}?return\\s+\\2[\\s\\S]{0,2000}?\\}" +
    ")",
    Pattern.DOTALL
);


  // old?
  private static final Pattern functionPatternOld = Pattern.compile(
      "function\\(\\s*(\\w+)\\s*\\)\\s*\\{" +
          "var\\s*(\\w+)=\\1\\[" + VARIABLE_PART + "\\[\\d+\\]\\]\\(" + VARIABLE_PART + "\\[\\d+\\]\\)" +
          ".*?catch\\(\\s*(\\w+)\\s*\\)\\s*\\{" +
          "\\s*return.*?\\+\\s*\\1\\s*}" +
          "\\s*return\\s*\\2\\[" + VARIABLE_PART + "\\[\\d+\\]\\]\\(" + VARIABLE_PART + "\\[\\d+\\]\\)};",
      Pattern.DOTALL);

  private final ConcurrentMap<String, SignatureCipher> cipherCache;
  private final Set<String> dumpedScriptUrls;
  private final ScriptEngine scriptEngine;
  private final Object cipherLoadLock;

  protected volatile CachedPlayerScript cachedPlayerScript;

  /**
   * Create a new signature cipher manager
   */
  public SignatureCipherManager() {
    this.cipherCache = new ConcurrentHashMap<>();
    this.dumpedScriptUrls = new HashSet<>();
    this.scriptEngine = new RhinoScriptEngineFactory().getScriptEngine();
    this.cipherLoadLock = new Object();
  }

  /**
   * Produces a valid playback URL for the specified track
   *
   * @param httpInterface HTTP interface to use
   * @param playerScript  Address of the script which is used to decipher signatures
   * @param format        The track for which to get the URL
   * @return Valid playback URL
   * @throws IOException On network IO error
   */
  @NotNull
  public URI resolveFormatUrl(@NotNull HttpInterface httpInterface,
                              @NotNull String playerScript,
                              @NotNull StreamFormat format) throws IOException {
    String signature = format.getSignature();
    String nParameter = format.getNParameter();
    URI initialUrl = format.getUrl();

    URIBuilder uri = new URIBuilder(initialUrl);
    SignatureCipher cipher = getCipherScript(httpInterface, playerScript);

    if (!DataFormatTools.isNullOrEmpty(signature)) {
      try {
        uri.setParameter(format.getSignatureKey(), cipher.apply(signature, scriptEngine));
      } catch (ScriptException | NoSuchMethodException e) {
        dumpProblematicScript(cipherCache.get(playerScript).rawScript, playerScript, "Can't transform s parameter " + signature);
      }
    }
      

    if (!DataFormatTools.isNullOrEmpty(nParameter)) {
      try {
        String transformed = cipher.transform(nParameter, scriptEngine);
        String logMessage = null;

        if (transformed == null) {
          logMessage = "Transformed n parameter is null, n function possibly faulty";
        } else if (nParameter.equals(transformed)) {
          logMessage = "Transformed n parameter is the same as input, n function possibly short-circuited";
        } else if (transformed.startsWith("enhanced_except_") || transformed.endsWith("_w8_" + nParameter)) {
          logMessage = "N function did not complete due to exception";
        }

        if (logMessage != null) {
            log.warn("{} (in: {}, out: {}, player script: {}, source version: {})",
                logMessage, nParameter, transformed, playerScript, YoutubeSource.VERSION);
        }

        uri.setParameter("n", transformed);
      } catch (ScriptException | NoSuchMethodException e) {
        // URLs can still be played without a resolved n parameter. It just means they're
        // throttled. But we shouldn't throw an exception anyway as it's not really fatal.
        dumpProblematicScript(cipherCache.get(playerScript).rawScript, playerScript, "Can't transform n parameter " + nParameter + " with " + cipher.nFunction + " n function");
      }
    }

    try {
      return uri.build(); // setParameter("ratebypass", "yes")  -- legacy parameter that will give 403 if tampered with.
    } catch (URISyntaxException e) {
      throw new RuntimeException(e);
    }
  }

  private CachedPlayerScript getPlayerScript(@NotNull HttpInterface httpInterface) {
    synchronized (cipherLoadLock) {
      try (CloseableHttpResponse response = httpInterface.execute(new HttpGet("https://www.youtube.com/embed/"))) {
        HttpClientTools.assertSuccessWithContent(response, "fetch player script (embed)");

        String responseText = EntityUtils.toString(response.getEntity());
        String scriptUrl = DataFormatTools.extractBetween(responseText, "\"jsUrl\":\"", "\"");

        if (scriptUrl == null) {
          throw throwWithDebugInfo(log, null, "no jsUrl found", "html", responseText);
        }

        return (cachedPlayerScript = new CachedPlayerScript(scriptUrl));
      } catch (IOException e) {
        throw ExceptionTools.toRuntimeException(e);
      }
    }
  }

  public CachedPlayerScript getCachedPlayerScript(@NotNull HttpInterface httpInterface) {
    if (cachedPlayerScript == null || System.currentTimeMillis() >= cachedPlayerScript.expireTimestampMs) {
      synchronized (cipherLoadLock) {
        if (cachedPlayerScript == null || System.currentTimeMillis() >= cachedPlayerScript.expireTimestampMs) {
          return getPlayerScript(httpInterface);
        }
      }
    }

    return cachedPlayerScript;
  }

  public SignatureCipher getCipherScript(@NotNull HttpInterface httpInterface,
                                         @NotNull String cipherScriptUrl) throws IOException {
    SignatureCipher cipherKey = cipherCache.get(cipherScriptUrl);

    if (cipherKey == null) {
      synchronized (cipherLoadLock) {
        log.debug("Parsing player script {}", cipherScriptUrl);

        try (CloseableHttpResponse response = httpInterface.execute(new HttpGet(parseTokenScriptUrl(cipherScriptUrl)))) {
          int statusCode = response.getStatusLine().getStatusCode();

          if (!HttpClientTools.isSuccessWithContent(statusCode)) {
            throw new IOException("Received non-success response code " + statusCode + " from script url " +
                cipherScriptUrl + " ( " + parseTokenScriptUrl(cipherScriptUrl) + " )");
          }

          cipherKey = extractFromScript(EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8), cipherScriptUrl);
          cipherCache.put(cipherScriptUrl, cipherKey);
        }
      }
    }

    return cipherKey;
  }

  private List<String> getQuotedFunctions(@Nullable String... functionNames) {
    return Stream.of(functionNames)
        .filter(Objects::nonNull)
        .map(Pattern::quote)
        .collect(Collectors.toList());
  }

  private void dumpProblematicScript(@NotNull String script, @NotNull String sourceUrl,
                                     @NotNull String issue) {
    if (!dumpedScriptUrls.add(sourceUrl)) {
      return;
    }

    try {
      Path path = Files.createTempFile("lavaplayer-yt-player-script", ".js");
      Files.write(path, script.getBytes(StandardCharsets.UTF_8));

      log.error("Problematic YouTube player script {} detected (issue detected with script: {}). Dumped to {} (Source version: {})",
          sourceUrl, issue, path.toAbsolutePath(), YoutubeSource.VERSION);
    } catch (Exception e) {
      log.error("Failed to dump problematic YouTube player script {} (issue detected with script: {})", sourceUrl, issue);
    }
  }

  private SignatureCipher extractFromScript(@NotNull String script, @NotNull String sourceUrl) {
  // helper lambdas (anonymous inner style)
  final java.util.function.BiFunction<String, Integer, Integer> findFunctionStart = (s, pos) -> {
    // scan backwards from pos to find "function" or "=function" or identifier "=" (assignment)
    int i = pos;
    while (i > 0) {
      // look for "function" keyword
      int idx = s.lastIndexOf("function", i);
      int assignIdx = s.lastIndexOf("=", i);
      int varIdx = s.lastIndexOf("var", i);
      int candidate = Math.max(idx, Math.max(assignIdx, varIdx));
      if (candidate < 0) return -1;
      // if "function" is present and before assign/var, prefer it
      if (idx >= 0 && idx == candidate) {
        return idx;
      }
      // if we saw "var" or "=", step back a bit and continue searching for "function"
      i = candidate - 1;
    }
    return -1;
  };

  final java.util.function.BiFunction<String, Integer, Integer> findEnclosingBlockEnd = (s, start) -> {
    // given position of '{' (start), find matching '}' with brace counting
    int len = s.length();
    int i = start;
    int depth = 0;
    for (; i < len; i++) {
      char c = s.charAt(i);
      if (c == '{') depth++;
      else if (c == '}') {
        depth--;
        if (depth == 0) return i;
      }
    }
    return -1;
  };

  // 1) timestamp
  Matcher scriptTimestamp = TIMESTAMP_PATTERN.matcher(script);
  if (!scriptTimestamp.find()) {
    scriptExtractionFailed(script, sourceUrl, ExtractionFailureType.TIMESTAMP_NOT_FOUND);
  }
  String timestamp = scriptTimestamp.group(2);

  // 2) global vars (existing logic)
  Matcher globalVarsMatcher = GLOBAL_VARS_PATTERN.matcher(script);
  if (!globalVarsMatcher.find()) {
    scriptExtractionFailed(script, sourceUrl, ExtractionFailureType.VARIABLES_NOT_FOUND);
  }
  String globalVars = globalVarsMatcher.group("code");

  // 3) Find candidate sig-function and n-function by searching for canonical tokens
  String sigFunction = null;
  String sigActions = "";
  String nFunction = null;

  // Utility: find nearest enclosing function/assignment around an index, using brace matching
  java.util.function.Function<Integer, String> extractEnclosingFunction = (posIndex) -> {
    int len = script.length();
    // find opening brace '{' after nearest "function" or "function(" occurrence
    int openBrace = script.indexOf('{', posIndex);
    if (openBrace < 0) return null;
    int endBrace = findEnclosingBlockEnd.apply(script, openBrace);
    if (endBrace < 0) return null;
    // include potential "var name = function(...){...}" prefix by scanning backwards a bit
    int scanBack = Math.max(0, posIndex - 120);
    int prefixStart = script.lastIndexOf("function", posIndex);
    if (prefixStart < 0) {
      // try to find an assignment start
      int assign = script.lastIndexOf("=", posIndex);
      int varkw = script.lastIndexOf("var", posIndex);
      int start = Math.max(assign, varkw);
      if (start > scanBack) prefixStart = start;
      else prefixStart = Math.max(scanBack, prefixStart);
    }
    // clamp prefixStart
    if (prefixStart < 0) prefixStart = scanBack;
    String candidate = script.substring(prefixStart, endBrace + 1);
    return candidate;
  };

  // Search function for patterns: split("") + join("") (sig) OR split/join or helpers (n)
  // We'll do a two-pass approach: try to find signature decipher (sig) first then n.

  // Try to locate signature function: search for ".split(\"\"" and ".join(\"\""
  int idx = 0;
  boolean sigFound = false;
  while (true) {
    int sidx = script.indexOf(".split(\"", idx);
    if (sidx < 0) break;
    // check if join appears nearby
    int jidx = script.indexOf(".join(\"", sidx);
    if (jidx > 0 && jidx - sidx < 4000) {
      // extract enclosing function near sidx
      int funcKeyword = script.lastIndexOf("function", sidx);
      int assignKeyword = script.lastIndexOf("=function", sidx);
      int startPos = Math.max(funcKeyword, assignKeyword);
      if (startPos < 0) startPos = Math.max(0, sidx - 120);
      String candidate = extractEnclosingFunction.apply(startPos);
      if (candidate != null && candidate.length() > 0) {
        // sanity: require that param is returned or joined
        if (candidate.contains(".join(\"") || candidate.matches("(?s).*return\\s+[a-zA-Z0-9_$]+.*")) {
          sigFunction = candidate;
          sigFound = true;
          break;
        }
      }
    }
    idx = sidx + 6;
  }

  // If we didn't find a sig function via split/join, try to find an assignment of form: name=function(a){ ... return a; }
  if (!sigFound) {
    Pattern altSig = Pattern.compile("([A-Za-z0-9_$]{1,20})\\s*=\\s*function\\s*\\(\\s*([A-Za-z0-9_$]+)\\s*\\)\\s*\\{", Pattern.DOTALL);
    Matcher malt = altSig.matcher(script);
    if (malt.find()) {
      int p = malt.start();
      String cand = extractEnclosingFunction.apply(p);
      if (cand != null && cand.contains(".join(\"")) {
        sigFunction = cand;
        sigFound = true;
      }
    }
  }

  // If sig still not found: try older ACTIONS_PATTERN (helper object) fallback
  String sigHelperObjName = null;
  if (!sigFound) {
    Matcher actions = ACTIONS_PATTERN.matcher(script);
    if (actions.find()) {
      sigActions = actions.group(0);
      sigHelperObjName = actions.group(1);
    }
    // try to also find an inline function name referring to that actions name
    // (best-effort) - fall through
  }

  // Now find an n() transform. Typical signs: ".split(\"\")", helper calls like "h(a,3)", or "return a.join('')"
  // We search for short functions that either contain split/join or call a helper with the arg and return it.
  Pattern nLikeSplit = Pattern.compile("function\\s*(?:[A-Za-z0-9_$]{0,14})\\s*\\(\\s*([A-Za-z0-9_$]+)\\s*\\)\\s*\\{[\\s\\S]{0,1200}?split\\s*\\(\\s*['\"]?['\"]?\\s*\\)[\\s\\S]{0,1200}?join\\s*\\(\\s*['\"]?['\"]?\\s*\\)[\\s\\S]{0,1200}?\\}", Pattern.DOTALL);
  Matcher nLike = nLikeSplit.matcher(script);
  if (nLike.find()) {
    int pos = nLike.start();
    nFunction = extractEnclosingFunction.apply(pos);
  } else {
    // helper-call style: function foo(a){ a = h(a,3); return a; }
    Pattern nHelperCall = Pattern.compile("function\\s*(?:[A-Za-z0-9_$]{0,14})\\s*\\(\\s*([A-Za-z0-9_$]+)\\s*\\)\\s*\\{[\\s\\S]{0,1200}?[A-Za-z0-9_$]{1,6}\\s*\\(\\s*\\1\\s*,\\s*\\d+\\s*\\)[\\s\\S]{0,1200}?return\\s+\\1[\\s\\S]{0,1200}?\\}", Pattern.DOTALL);
    Matcher hmat = nHelperCall.matcher(script);
    if (hmat.find()) {
      int pos = hmat.start();
      nFunction = extractEnclosingFunction.apply(pos);
    } else {
      // assignment style: name=function(a){ ... }
      Pattern nAssign = Pattern.compile("[A-Za-z0-9_$]{1,20}\\s*=\\s*function\\s*\\(\\s*([A-Za-z0-9_$]+)\\s*\\)\\s*\\{", Pattern.DOTALL);
      Matcher assignM = nAssign.matcher(script);
      if (assignM.find()) {
        int pos = assignM.start();
        String cand = extractEnclosingFunction.apply(pos);
        // require some sign it is an n transform (split/join or helper call)
        if (cand != null && (
    cand.contains(".split(\"") ||
    cand.contains(".join(\"") ||
    cand.matches(".*\\([A-Za-z0-9_$]{1,6}\\s*,\\s*\\d+\\).*")
)) {
          nFunction = cand;
        }
      }
    }
  }

  // If we have sigFunction but missing helper object, try to extract referenced helper object names from the sigFunction body
  if (sigFunction != null && (sigActions == null || sigActions.isEmpty())) {
    // look for patterns like "Xy.z(a,3)" or "XyA(a,3)" inside sigFunction to identify helper object names
    Pattern helperName = Pattern.compile("([A-Za-z0-9_$]{1,8})\\.([A-Za-z0-9_$]{1,8})\\s*\\(");
    Matcher hnm = helperName.matcher(sigFunction);
    if (hnm.find()) {
      String objName = hnm.group(1);
      // find var objName = { ... };
      Pattern objPat = Pattern.compile("(var\\s+" + Pattern.quote(objName) + "\\s*=\\s*\\{[\\s\\S]{0,2000}?\\};)");
      Matcher objM = objPat.matcher(script);
      if (objM.find()) {
        sigActions = objM.group(1);
      } else {
        // sometimes helper object assigned without var
        objPat = Pattern.compile("(" + Pattern.quote(objName) + "\\s*=\\s*\\{[\\s\\S]{0,2000}?\\};)");
        objM = objPat.matcher(script);
        if (objM.find()) {
          sigActions = objM.group(1);
        }
      }
    }
  }

  // final fallback checks: older ACTIONS_PATTERN and SIG_FUNCTION_PATTERN
  if (sigFunction == null) {
    Matcher actions = ACTIONS_PATTERN.matcher(script);
    if (actions.find()) {
      sigActions = actions.group(0);
      // try to find sig function by locating usages of the actions object
      String objName = null;
      Pattern objNamePat = Pattern.compile("var\\s+([A-Za-z0-9_$]{1,12})\\s*=\\s*\\{");
      Matcher on = objNamePat.matcher(sigActions);
      if (on.find()) objName = on.group(1);
      if (objName != null) {
        Pattern usePat = Pattern.compile(Pattern.quote(objName) + "\\.[A-Za-z0-9_$]{1,12}\\s*\\(");
        Matcher up = usePat.matcher(script);
        if (up.find()) {
          int pos = Math.max(0, up.start() - 80);
          sigFunction = extractEnclosingFunction.apply(pos);
        }
      }
    }
  }

  // If still missing sigFunction or nFunction, dump and fail gracefully
  if (sigFunction == null) {
    dumpProblematicScript(script, sourceUrl, "must find decipher function (sig)");
    throw new ScriptExtractionException("Must find decipher function from script: " + sourceUrl, ExtractionFailureType.DECIPHER_FUNCTION_NOT_FOUND);
  }

  if (nFunction == null) {
    // Not fatal — some scripts don't expose a transform; we'll continue without n transform but dump for analysis
    dumpProblematicScript(script, sourceUrl, "n function not found; continuing without n transform");
    log.warn("No n() transformation function identified in player script {}. Continuing without n transform; streams may be throttled.", sourceUrl);
    nFunction = "";
  }

  // Remove short-circuit in nFunction if present
  if (nFunction != null && !nFunction.isEmpty()) {
    String nfParameterName = DataFormatTools.extractBetween(nFunction, "(", ")");
    if (nfParameterName != null && !nfParameterName.isEmpty()) {
      nFunction = nFunction.replaceAll("if\\s*\\(typeof\\s*[^\\s()]+\\s*===?.*?\\)return\\s+" + Pattern.quote(nfParameterName) + "\\s*;?", "");
    }
  }

  // Return new SignatureCipher (timestamp, globalVars, actions, sigFunction, nFunction, fullScript)
  return new SignatureCipher(timestamp, globalVars == null ? "" : globalVars, sigActions == null ? "" : sigActions, sigFunction, nFunction == null ? "" : nFunction, script);
}

  private void scriptExtractionFailed(String script, String sourceUrl, ExtractionFailureType failureType) {
    dumpProblematicScript(script, sourceUrl, "must find " + failureType.friendlyName);
    throw new ScriptExtractionException("Must find " + failureType.friendlyName + " from script: " + sourceUrl, failureType);
  }

  private static String extractDollarEscapedFirstGroup(@NotNull Pattern pattern, @NotNull String text) {
    Matcher matcher = pattern.matcher(text);
    return matcher.find() ? matcher.group(1).replace("$", "\\$") : null;
  }

  private static URI parseTokenScriptUrl(@NotNull String urlString) {
    try {
      if (urlString.startsWith("//")) {
        return new URI("https:" + urlString);
      } else if (urlString.startsWith("/")) {
        return new URI("https://www.youtube.com" + urlString);
      } else {
        return new URI(urlString);
      }
    } catch (URISyntaxException e) {
      throw new RuntimeException(e);
    }
  }

  public static class CachedPlayerScript {
    public final String url;
    public final long expireTimestampMs;

    protected CachedPlayerScript(@NotNull String url) {
      this.url = url;
      this.expireTimestampMs = System.currentTimeMillis() + TimeUnit.DAYS.toMillis(1);
    }
  }
}
