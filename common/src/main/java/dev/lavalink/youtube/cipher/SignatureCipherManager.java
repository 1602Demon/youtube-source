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

  // --- Replace the existing pattern constants with these more permissive/fallback patterns ---
  private static final Pattern TIMESTAMP_PATTERN = Pattern.compile("(?:signatureTimestamp|sts)\\s*[:=]\\s*(\\d+)");
  // global vars: either "var a = '...'.split('x')" or "var a = ['x','y',...]" or "window['...']=..."
  private static final Pattern GLOBAL_VARS_PATTERN = Pattern.compile(
      "(?s)(?:var|let)\\s+([A-Za-z0-9_$]+)\\s*=\\s*(?:\"[^\"]*\"\\.split\\(\"[^\"]*\"\\)|'[^']*'\\.split\\('[^']*'\\)|\\[[^\\]]+\\])"
  );
  // object containing actions - more permissive; try to find a "var X = { ... }" that contains functions
  private static final Pattern ACTIONS_PATTERN = Pattern.compile(
      "(?s)var\\s+([A-Za-z0-9_$]+)\\s*=\\s*\\{\\s*(?:[^{}]*?function[^{}]*?\\}\\s*,\\s*){1,6}[^}]*\\}"
  );
  // signature function (looking for function that operates on a string and uses common ops)
  private static final Pattern SIG_FUNCTION_PATTERN = Pattern.compile(
      "(?s)function\\s*([A-Za-z0-9_$]*)\\s*\\(\\s*([A-Za-z0-9_$]+)\\s*\\)\\s*\\{[^}]{20,1000}?(?:reverse|splice|slice|join|split|charAt|push)[^}]{0,1000}?\\}"
  );
  // n-function (heuristic): function that takes parameter and accesses arrays/indices and/or has "catch" branches
  private static final Pattern N_FUNCTION_PATTERN = Pattern.compile(
      "(?s)function\\s*\\(?\\s*([A-Za-z0-9_$]+)\\s*\\)?\\s*\\{[^}]{20,1000}?(?:\\[\\d+\\]|catch\\(|try\\{|return[^;]{0,200}n|enhanced_except_)[^}]{0,1000}?\\}"
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

  // --- Replace extractFromScript(...) with this defensive implementation ---
  private SignatureCipher extractFromScript(@NotNull String script, @NotNull String sourceUrl) {
    // attempt timestamp
    Matcher scriptTimestamp = TIMESTAMP_PATTERN.matcher(script);
    if (!scriptTimestamp.find()) {
      scriptExtractionFailed(script, sourceUrl, ExtractionFailureType.TIMESTAMP_NOT_FOUND);
    }

    String timestamp = scriptTimestamp.group(1);

    // Attempt to find global vars array/string.split(...) block
    String globalVars = null;
    Matcher globalVarsMatcher = GLOBAL_VARS_PATTERN.matcher(script);
    if (globalVarsMatcher.find()) {
      // extract surrounding snippet (include some lines before/after to preserve context)
      int start = Math.max(0, globalVarsMatcher.start() - 200);
      int end = Math.min(script.length(), globalVarsMatcher.end() + 200);
      globalVars = script.substring(start, end);
    }

    // Try a few fallback searches for globalVars if not found
    if (globalVars == null) {
      // fallback: search for any ".split(" array or any array literal near "var.*=\\["
      Pattern alt = Pattern.compile("(?s)(?:var|let)\\s+[A-Za-z0-9_$]+\\s*=\\s*(?:\\[[^\\]]+\\]|\"[^\"]*\"\\.split\\([^)]*\\))");
      Matcher mAlt = alt.matcher(script);
      if (mAlt.find()) {
        int start = Math.max(0, mAlt.start() - 200);
        int end = Math.min(script.length(), mAlt.end() + 200);
        globalVars = script.substring(start, end);
      }
    }

    if (globalVars == null) {
      scriptExtractionFailed(script, sourceUrl, ExtractionFailureType.VARIABLES_NOT_FOUND);
    }

    // Find action object (a var = { ... } that contains function members)
    String sigActions = null;
    Matcher sigActionsMatcher = ACTIONS_PATTERN.matcher(script);
    if (sigActionsMatcher.find()) {
      int start = Math.max(0, sigActionsMatcher.start() - 50);
      int end = Math.min(script.length(), sigActionsMatcher.end() + 10);
      sigActions = script.substring(start, end);
    } else {
      // fallback: try to locate an object literal assigned to a variable that contains function keywords
      Pattern objAlt = Pattern.compile("(?s)([A-Za-z0-9_$]{1,40})\\s*=\\s*\\{[^}]{30,2000}\\}");
      Matcher altM = objAlt.matcher(script);
      while (altM.find()) {
        String candidate = script.substring(Math.max(0, altM.start() - 20), Math.min(script.length(), altM.end() + 20));
        if (candidate.contains("function") || candidate.contains(":function")) {
          sigActions = candidate;
          break;
        }
      }
    }
    if (sigActions == null) {
      scriptExtractionFailed(script, sourceUrl, ExtractionFailureType.SIG_ACTIONS_NOT_FOUND);
    }

    // Find signature function
    String sigFunction = null;
    Matcher sigFunctionMatcher = SIG_FUNCTION_PATTERN.matcher(script);
    if (sigFunctionMatcher.find()) {
      int start = Math.max(0, sigFunctionMatcher.start() - 20);
      int end = Math.min(script.length(), sigFunctionMatcher.end() + 4);
      sigFunction = script.substring(start, end);
    } else {
      // fallback: look for inline function assigned to a variable or an object method that contains the sig ops
      Pattern altSig = Pattern.compile("(?s)([A-Za-z0-9_$]{1,60})\\s*:\\s*function\\s*\\([^)]*\\)\\s*\\{[^}]{20,1000}\\}");
      Matcher altSigM = altSig.matcher(sigActions != null ? sigActions : script);
      if (altSigM.find()) {
        sigFunction = altSigM.group(0);
      }
    }
    if (sigFunction == null) {
      scriptExtractionFailed(script, sourceUrl, ExtractionFailureType.DECIPHER_FUNCTION_NOT_FOUND);
    }

    // Find n-function
    String nFunction = null;
    Matcher nFunctionMatcher = N_FUNCTION_PATTERN.matcher(script);
    if (nFunctionMatcher.find()) {
      int start = Math.max(0, nFunctionMatcher.start() - 20);
      int end = Math.min(script.length(), nFunctionMatcher.end() + 4);
      nFunction = script.substring(start, end);
    } else {
      // fallback: try to find any function that references 'n' param or includes 'enhanced_except' or similar
      Pattern altN = Pattern.compile("(?s)function\\s*\\(?\\s*[A-Za-z0-9_$]+\\s*\\)?\\s*\\{[^}]{30,1000}(?:enhanced_except_|_w8_|n\\))[^}]*\\}");
      Matcher altNM = altN.matcher(script);
      if (altNM.find()) {
        nFunction = script.substring(Math.max(0, altNM.start() - 20), Math.min(script.length(), altNM.end() + 4));
      }
    }

    if (nFunction == null) {
      // Not fatal — the n parameter may be missing in some formats; we'll still proceed but warn
      log.warn("N function not found in player script {} — continuing without n transform", sourceUrl);
      nFunction = "";
    }

    // remove short circuit from nFunction if present (similar to previous logic)
    if (!nFunction.isEmpty()) {
      String nfParameterName = DataFormatTools.extractBetween(nFunction, "(", ")");
      if (nfParameterName != null) {
        nFunction = nFunction.replaceAll("if\\s*\\(typeof\\s*[^\\s()]+\\s*===?.*?\\)return\\s*" + Pattern.quote(nfParameterName) + "\\s*;?", "");
      }
    }

    // Return the cipher
    return new SignatureCipher(timestamp, globalVars, sigActions, sigFunction, nFunction, script);
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
