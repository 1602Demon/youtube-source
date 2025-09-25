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

  // timestamp
  private static final Pattern TIMESTAMP_PATTERN = Pattern.compile("(signatureTimestamp|sts)[=:](\\d+)");

  // the giant split array at top of script
  private static final Pattern GLOBAL_VARS_PATTERN = Pattern.compile(
      "var\\s+([a-zA-Z0-9_$]+)\\s*=\\s*\"[^\"]*\"\\.split\\(\";\"\\)"
  );

  // object with swap/reverse/splice etc.
  private static final Pattern ACTIONS_PATTERN = Pattern.compile(
      "var\\s+([$A-Za-z0-9_]+)\\s*=\\s*\\{[^}]+\\}\\s*;"
  );

  // sig function: function(a){a=a.split("");...return a.join("")}
  private static final Pattern SIG_FUNCTION_PATTERN = Pattern.compile(
      "function\\s*\\(\\s*(" + VARIABLE_PART + ")\\s*\\)\\s*\\{[^}]*?return\\s*\\1\\.join\\(\"\"\\)\\s*;?\\}",
      Pattern.DOTALL
  );

  // n function: function(b){var c=b.split("");...return c.join("")}
  private static final Pattern N_FUNCTION_PATTERN = Pattern.compile(
      "function\\s*\\(\\s*(" + VARIABLE_PART + ")\\s*\\)\\s*\\{[^}]*?return\\s*[a-zA-Z0-9_$]+\\.join\\(\"\"\\)\\s*;?\\}",
      Pattern.DOTALL
  );

  private final ConcurrentMap<String, SignatureCipher> cipherCache;
  private final Set<String> dumpedScriptUrls;
  private final ScriptEngine scriptEngine;
  private final Object cipherLoadLock;

  protected volatile CachedPlayerScript cachedPlayerScript;

  public SignatureCipherManager() {
    this.cipherCache = new ConcurrentHashMap<>();
    this.dumpedScriptUrls = new HashSet<>();
    this.scriptEngine = new RhinoScriptEngineFactory().getScriptEngine();
    this.cipherLoadLock = new Object();
  }

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
        dumpProblematicScript(cipherCache.get(playerScript).rawScript, playerScript,
            "Can't transform s parameter " + signature);
      }
    }

    if (!DataFormatTools.isNullOrEmpty(nParameter)) {
      try {
        String transformed = cipher.transform(nParameter, scriptEngine);
        if (transformed == null || transformed.equals(nParameter)) {
          log.warn("N transform may have failed (in: {}, out: {}, script: {})",
              nParameter, transformed, playerScript);
        }
        uri.setParameter("n", transformed);
      } catch (ScriptException | NoSuchMethodException e) {
        dumpProblematicScript(cipherCache.get(playerScript).rawScript, playerScript,
            "Can't transform n parameter " + nParameter);
      }
    }

    try {
      return uri.build();
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

        try (CloseableHttpResponse response =
                 httpInterface.execute(new HttpGet(parseTokenScriptUrl(cipherScriptUrl)))) {
          int statusCode = response.getStatusLine().getStatusCode();

          if (!HttpClientTools.isSuccessWithContent(statusCode)) {
            throw new IOException("Bad response " + statusCode + " from " + cipherScriptUrl);
          }

          cipherKey = extractFromScript(EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8), cipherScriptUrl);
          cipherCache.put(cipherScriptUrl, cipherKey);
        }
      }
    }

    return cipherKey;
  }

  private SignatureCipher extractFromScript(@NotNull String script, @NotNull String sourceUrl) {
    Matcher scriptTimestamp = TIMESTAMP_PATTERN.matcher(script);
    if (!scriptTimestamp.find()) {
      scriptExtractionFailed(script, sourceUrl, ExtractionFailureType.TIMESTAMP_NOT_FOUND);
    }

    Matcher globalVarsMatcher = GLOBAL_VARS_PATTERN.matcher(script);
    if (!globalVarsMatcher.find()) {
      scriptExtractionFailed(script, sourceUrl, ExtractionFailureType.VARIABLES_NOT_FOUND);
    }

    Matcher sigActionsMatcher = ACTIONS_PATTERN.matcher(script);
    if (!sigActionsMatcher.find()) {
      scriptExtractionFailed(script, sourceUrl, ExtractionFailureType.SIG_ACTIONS_NOT_FOUND);
    }

    Matcher sigFunctionMatcher = SIG_FUNCTION_PATTERN.matcher(script);
    if (!sigFunctionMatcher.find()) {
      scriptExtractionFailed(script, sourceUrl, ExtractionFailureType.DECIPHER_FUNCTION_NOT_FOUND);
    }

    Matcher nFunctionMatcher = N_FUNCTION_PATTERN.matcher(script);
    if (!nFunctionMatcher.find()) {
      scriptExtractionFailed(script, sourceUrl, ExtractionFailureType.N_FUNCTION_NOT_FOUND);
    }

    String timestamp = scriptTimestamp.group(2);
    String globalVars = globalVarsMatcher.group(0);
    String sigActions = sigActionsMatcher.group(0);
    String sigFunction = sigFunctionMatcher.group(0);
    String nFunction = nFunctionMatcher.group(0);

    return new SignatureCipher(timestamp, globalVars, sigActions, sigFunction, nFunction, script);
  }

  private void scriptExtractionFailed(String script, String sourceUrl, ExtractionFailureType failureType) {
    dumpProblematicScript(script, sourceUrl, "must find " + failureType.friendlyName);
    throw new ScriptExtractionException("Must find " + failureType.friendlyName + " from script: " + sourceUrl, failureType);
  }

  private void dumpProblematicScript(@NotNull String script, @NotNull String sourceUrl,
                                     @NotNull String issue) {
    if (!dumpedScriptUrls.add(sourceUrl)) {
      return;
    }
    try {
      Path path = Files.createTempFile("yt-player-script", ".js");
      Files.write(path, script.getBytes(StandardCharsets.UTF_8));
      log.error("Problematic YouTube script {} ({}) dumped to {}", sourceUrl, issue, path.toAbsolutePath());
    } catch (Exception e) {
      log.error("Failed to dump problematic YouTube script {}", sourceUrl, e);
    }
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
