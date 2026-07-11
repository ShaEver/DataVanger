using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Classification;
using DataVanger.Core;
using DataVanger.Core.Abstractions;
using DataVanger.Core.Domain;
using DataVanger.Detection;
using DataVanger.Engine;
using DataVanger.Memory;
using DataVanger.Memory.Readers;
using DataVanger.Memory.Rules;
using DataVanger.Reputation;
using static DataVanger.Tests.Fixtures.PeFactory;

// Phase 09 decomposition — Browser Extension Intelligence: context, trust, FP
// mitigation (legacy section 17). Faithful verbatim move; private Assert shim ->
// LegacyAssert.True. The legacy mega-[Fact] shared one ReputationEngine across
// sections 15 and 17; it is reconstructed here verbatim from section 15 so this
// [Fact] is self-contained (identical construction, no behaviour change).
// Filter: ~BrowserExtension.
public class BrowserExtensionTests
{
    private static void Assert(bool condition, string message) => LegacyAssert.True(condition, message);

    [Xunit.Fact]
    public async Task BrowserExtensionIntelligence_AllLegacyChecks()
    {
        // Reconstructed shared reputation engine (verbatim from legacy section 15).
        var repSettings = new AppSettings();
        var repDb = new SignatureDatabase();
        var repEngine = new ReputationEngine(repDb, repSettings);

// 17. Browser Extension Intelligence - context, trust, false-positive mitigation
// ============================================================================

var biContext = DataVanger.BrowserIntelligence.BrowserContextDetector.Detect(
    @"C:\Users\T\AppData\Local\Google\Chrome\User Data\Default\Extensions\cjpalhdlnbpafiamejdnhcphjbkeiagm\1.50.0_0\manifest.json");
Assert(biContext.IsExtensionContext
    && biContext.Browser == DataVanger.BrowserIntelligence.BrowserKind.Chrome
    && biContext.ExtensionId == "cjpalhdlnbpafiamejdnhcphjbkeiagm"
    && biContext.ExtensionVersion == "1.50.0_0",
    "BrowserContextDetector must recognise Chromium /Extensions/<id>/<version>/manifest.json layout.");

var biEdge = DataVanger.BrowserIntelligence.BrowserContextDetector.Detect(
    @"C:\Users\T\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\jmjflgjpcpepeafmmgdpfkogkghcpiha\2.1.0_0\background.js");
Assert(biEdge.IsExtensionContext && biEdge.Browser == DataVanger.BrowserIntelligence.BrowserKind.Edge,
    "BrowserContextDetector must recognise Edge extension layouts.");

var biFirefox = DataVanger.BrowserIntelligence.BrowserContextDetector.Detect(
    @"C:\Users\T\AppData\Roaming\Mozilla\Firefox\Profiles\abc.default\extensions\uBlock0@raymondhill.net.xpi");
Assert(biFirefox.IsExtensionContext && biFirefox.Browser == DataVanger.BrowserIntelligence.BrowserKind.Firefox,
    "BrowserContextDetector must recognise Firefox extension layouts.");

var biUnrelated = DataVanger.BrowserIntelligence.BrowserContextDetector.Detect(
    @"C:\Users\T\AppData\Local\NotABrowser\Stuff\manifest.json");
Assert(!biUnrelated.IsExtensionContext,
    "BrowserContextDetector must not claim browser context for unrelated AppData paths.");

var biProfileOnly = DataVanger.BrowserIntelligence.BrowserContextDetector.Detect(
    @"C:\Users\T\AppData\Local\Google\Chrome\User Data\Default\Cache\f_001234");
Assert(biProfileOnly.Browser == DataVanger.BrowserIntelligence.BrowserKind.Chrome && !biProfileOnly.IsExtensionContext,
    "BrowserContextDetector must recognise a Chrome profile root without claiming extension context for non-extension files.");

Assert(DataVanger.BrowserIntelligence.ExtensionPermissionCatalog.Classify("nativeMessaging")
       == DataVanger.BrowserIntelligence.PermissionRiskLevel.High,
    "nativeMessaging must be classified as high-risk permission.");
Assert(DataVanger.BrowserIntelligence.ExtensionPermissionCatalog.Classify("storage")
       == DataVanger.BrowserIntelligence.PermissionRiskLevel.Low,
    "storage must be classified as a low-risk permission.");
Assert(DataVanger.BrowserIntelligence.ExtensionPermissionCatalog.Classify("https://*/*")
       == DataVanger.BrowserIntelligence.PermissionRiskLevel.Moderate,
    "Wildcard host_permission https://*/* must be classified as moderate.");

const string benignManifestJson = """
{
  "manifest_version": 3,
  "name": "Test Modern Extension",
  "version": "1.2.3",
  "description": "A perfectly normal modern extension",
  "update_url": "https://clients2.google.com/service/update2/crx",
  "permissions": ["storage", "activeTab"],
  "host_permissions": ["https://example.com/*"],
  "background": { "service_worker": "background.js" }
}
""";
var benignManifest = DataVanger.BrowserIntelligence.ExtensionManifestParser.ParseFromText(benignManifestJson);
Assert(benignManifest.ParsedSuccessfully
    && benignManifest.ManifestVersion == 3
    && benignManifest.Name == "Test Modern Extension"
    && benignManifest.Permissions.Contains("storage")
    && benignManifest.HostPermissions.Contains("https://example.com/*"),
    "ManifestParser must parse a well-formed MV3 manifest and split permissions correctly.");

const string mv2Manifest = """
{
  "manifest_version": 2,
  "name": "Old extension",
  "version": "0.1",
  "permissions": ["tabs", "<all_urls>", "https://*/*", "storage"],
  "background": { "scripts": ["bg.js"] },
  "content_security_policy": "script-src 'self' 'unsafe-eval'; object-src 'self'"
}
""";
var mv2 = DataVanger.BrowserIntelligence.ExtensionManifestParser.ParseFromText(mv2Manifest);
Assert(mv2.ParsedSuccessfully && mv2.ManifestVersion == 2
    && mv2.HostPermissions.Any(p => p == "<all_urls>" || p == "https://*/*")
    && mv2.Permissions.Contains("tabs")
    && mv2.CspAllowsUnsafeEval,
    "ManifestParser must migrate MV2 host matches out of permissions and detect unsafe-eval in CSP.");

var malformedManifest = DataVanger.BrowserIntelligence.ExtensionManifestParser.ParseFromText("not really json");
Assert(!malformedManifest.ParsedSuccessfully && !string.IsNullOrEmpty(malformedManifest.ParseError),
    "ManifestParser must return ParseError on malformed input rather than throwing.");

string biTestDir = Path.Combine(Path.GetTempPath(), "datavanger-browser-ext-tests");
try { Directory.Delete(biTestDir, recursive: true); } catch (Exception) { /* temp cleanup - ignore if already removed */ }
Directory.CreateDirectory(biTestDir);

// 17a. Legitimate extension folder — webpack bundle + locales/icons.
string legitExt = Path.Combine(biTestDir, "legit", "abcdefghijklmnopabcdefghijklmnop", "1.0.0_0");
Directory.CreateDirectory(legitExt);
Directory.CreateDirectory(Path.Combine(legitExt, "_locales", "en"));
Directory.CreateDirectory(Path.Combine(legitExt, "_metadata"));
Directory.CreateDirectory(Path.Combine(legitExt, "icons"));
File.WriteAllText(Path.Combine(legitExt, "manifest.json"), benignManifestJson);
File.WriteAllText(Path.Combine(legitExt, "background.js"),
    "/*! For license information please see vendors.js.LICENSE.txt */\n"
    + "var __webpack_modules__={}; function __webpack_require__(id){return id}\n"
    + "webpackJsonp.push([[0],{}]);"
    + new string(' ', 256));
File.WriteAllText(Path.Combine(legitExt, "chunk-1234abcd.js"), "(self.webpackChunk=self.webpackChunk||[]).push([[1]]);");
File.WriteAllText(Path.Combine(legitExt, "vendor-9876fedc.js"), "Object.defineProperty(exports,'__esModule',{value:true});");

var bundleProfile = DataVanger.BrowserIntelligence.FrontendBundleDetector.Inspect(legitExt);
Assert(bundleProfile.IsRecognisedBundle && bundleProfile.MarkersFound.Count > 0,
    "FrontendBundleDetector must recognise webpack/vite/React markers in a real extension folder.");
Assert(bundleProfile.LooksLegitimatelyPackaged,
    "Bundle profile with _locales/_metadata/icons + chunked file names must look legitimately packaged.");

// 17b. AnalyzeManifest must downgrade modern legitimate extensions.
string fakeChromePrefix = Path.Combine(biTestDir, "fake-chrome");
// We do not enforce a real Chrome path here; we are testing trust-engine reductions purely from bundle + manifest hygiene.
var legitResult = DataVanger.BrowserIntelligence.BrowserExtensionIntelligence.AnalyzeManifest(
    Path.Combine(legitExt, "manifest.json"), localSeenCount: 6);
Assert(legitResult.Score <= 0,
    "Modern MV3 extension with webpack bundle, official update_url and local prevalence must stay non-alarming.");
Assert(legitResult.Evidence.All(e => !e.CanConfirmMalware),
    "BrowserExtensionIntelligence evidence must never be confirmable malware.");
Assert(legitResult.Evidence.Any(e => e.Description.Contains("bundle", StringComparison.OrdinalIgnoreCase)
                                  || e.Description.Contains("Pacote", StringComparison.OrdinalIgnoreCase)),
    "BrowserExtensionIntelligence must surface bundle/package context as explainable evidence.");

// 17c. Risky-permission extension — must produce evidence but never confirm.
string riskyExt = Path.Combine(biTestDir, "risky", "ponaabcdefghijklmnopabcdefghijkl", "0.0.1_0");
Directory.CreateDirectory(riskyExt);
const string riskyManifestJson = """
{
  "manifest_version": 2,
  "name": "Suspicious helper",
  "version": "0.0.1",
  "permissions": ["nativeMessaging", "debugger", "management", "proxy",
                  "cookies", "tabs", "webRequest", "webRequestBlocking",
                  "<all_urls>"],
  "background": { "scripts": ["bg.js"] },
  "content_security_policy": "script-src 'self' 'unsafe-eval' https://evil.example; object-src 'self'"
}
""";
File.WriteAllText(Path.Combine(riskyExt, "manifest.json"), riskyManifestJson);
File.WriteAllText(Path.Combine(riskyExt, "bg.js"), "console.log('plain');");

var riskyResult = DataVanger.BrowserIntelligence.BrowserExtensionIntelligence.AnalyzeManifest(
    Path.Combine(riskyExt, "manifest.json"));
Assert(riskyResult.Score > 0,
    "Extension declaring nativeMessaging+debugger+management+proxy must produce a positive risk score.");
Assert(riskyResult.Evidence.Any(e => e.Description.Contains("native messaging", StringComparison.OrdinalIgnoreCase)),
    "Trust engine must flag native messaging declarations.");
Assert(riskyResult.Evidence.Any(e => e.Description.Contains("unsafe-eval", StringComparison.OrdinalIgnoreCase)),
    "Trust engine must flag CSP unsafe-eval.");
Assert(riskyResult.Evidence.All(e => !e.CanConfirmMalware),
    "Even maximally risky permission combos must remain heuristic — never ConfirmedMalware.");
var riskyFinding = new ScanFinding
{
    Path = Path.Combine(riskyExt, "manifest.json"),
    Score = riskyResult.Score,
    Evidence = riskyResult.Evidence.ToList(),
};
Assert(ThreatClassificationPolicy.Classify(riskyFinding) != ThreatClass.ConfirmedMalware,
    "Anti-FP policy must keep browser-extension heuristics out of ConfirmedMalware classification.");
Assert(!ThreatClassificationPolicy.AllowsAutomaticAction(riskyFinding),
    "Browser-extension heuristic findings must not authorize automatic action.");

// 17d. Known-good extension id must remain trusted even with risky perms.
string knownGoodExt = Path.Combine(biTestDir, "known-good", "cjpalhdlnbpafiamejdnhcphjbkeiagm", "1.55.0_0");
Directory.CreateDirectory(knownGoodExt);
// Replace the extension id segment so BrowserContextDetector recognises the well-known id.
// (Layout is checked by regex; we still need a "Chromium-like" path for context detection.)
const string knownGoodManifestJson = """
{
  "manifest_version": 3,
  "name": "uBlock Origin",
  "version": "1.55.0",
  "update_url": "https://clients2.google.com/service/update2/crx",
  "permissions": ["storage", "scripting", "tabs", "webRequest", "webRequestBlocking", "<all_urls>"],
  "background": { "service_worker": "bg.js" }
}
""";
File.WriteAllText(Path.Combine(knownGoodExt, "manifest.json"), knownGoodManifestJson);
File.WriteAllText(Path.Combine(knownGoodExt, "bg.js"), "// service worker");
var knownGoodResult = DataVanger.BrowserIntelligence.BrowserExtensionIntelligence.AnalyzeManifest(
    Path.Combine(knownGoodExt, "manifest.json"));
Assert(knownGoodResult.Score < 2,
    "Well-known extension ids should keep heuristic score low even with broad permissions.");

// 17e. Side-loaded path must increase scrutiny.
var sideLoadedCtx = DataVanger.BrowserIntelligence.BrowserContextDetector.Detect(
    @"C:\Users\T\AppData\Local\Google\Chrome\User Data\external_extensions\Extensions\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0.0.1_0\manifest.json");
Assert(sideLoadedCtx.IsExtensionContext && sideLoadedCtx.IsSideLoadedPath,
    "BrowserContextDetector must mark external_extensions paths as side-loaded.");

// 17f. Detection module integration — only fires on manifest.json in Full profile.
var fullSettings = new AppSettings { AnalyzeBrowserExtensions = true };
var fullOptions = new ScanOptions { Profile = ScanProfile.Deep, ScanBrowserExtensions = true };
var fullContext = new ScanContext(
    fullOptions, fullSettings,
    runningProcessPaths: Array.Empty<string>(),
    persistenceExactPaths: Array.Empty<string>(),
    persistenceBlob: "");
var manifestTarget = new ScanTarget(new FileInfo(Path.Combine(legitExt, "manifest.json")));
var browserModule = new BrowserExtensionDetectionModule();
Assert(browserModule.Supports(manifestTarget, fullContext),
    "BrowserExtensionDetectionModule must support manifest.json in a Full profile with browser-extension scanning enabled.");
var quickOptions = new ScanOptions { Profile = ScanProfile.Fast, ScanBrowserExtensions = true };
var quickContext = new ScanContext(quickOptions, fullSettings, Array.Empty<string>(), Array.Empty<string>(), "");
Assert(!browserModule.Supports(manifestTarget, quickContext),
    "BrowserExtensionDetectionModule must not fire outside the Full profile (avoid Quick/Standard noise).");

var moduleEvidence = await browserModule.AnalyzeAsync(manifestTarget, fullContext, CancellationToken.None);
Assert(moduleEvidence.All(e => !e.CanConfirmMalware),
    "Detection-module evidence must never confirm malware on its own.");
Assert(moduleEvidence.Any(e => e.Category == "Browser"),
    "Detection-module must emit Browser-category evidence.");

// 17g. Reputation engine integration — legitimate browser-extension context must downgrade static-only heuristics.
var repBrowserSubject = new ReputationSubject
{
    Sha256 = new string('B', 64),
    Path = Path.Combine(legitExt, "manifest.json"),
    Extension = ".json",
    BaseScore = 9,
    LastWriteUtc = DateTime.UtcNow.AddDays(-5),
    Evidence = moduleEvidence.ToArray(),
};
var repBrowserEval = repEngine.Evaluate(repBrowserSubject,
    new LocalReputationEntry { SHA256 = repBrowserSubject.Sha256, SeenCount = 4 });
Assert(repBrowserEval.AdjustedScore < RiskThresholds.High,
    "Reputation engine must keep legitimate browser-extension static evidence below High after browser-aware downgrade.");

// 17h. Backwards-compatible facade still works.
// Compare the legacy facade with a direct BrowserExtensionIntelligence call using the same default parameters.
// The earlier legitResult intentionally uses localSeenCount: 6, which adds prevalence evidence and makes
// evidence-count comparisons invalid even when the facade delegates correctly.
var directDefaultBrowserResult = DataVanger.BrowserIntelligence.BrowserExtensionIntelligence.AnalyzeManifest(
    Path.Combine(legitExt, "manifest.json"));
var legacyResult = DataVanger.Core.BrowserExtensionAnalyzer.AnalyzeManifest(
    Path.Combine(legitExt, "manifest.json"));
Assert(legacyResult.Score == directDefaultBrowserResult.Score
       && legacyResult.Evidence.Count == directDefaultBrowserResult.Evidence.Count,
    "Legacy BrowserExtensionAnalyzer.AnalyzeManifest must delegate to BrowserExtensionIntelligence.");

try { Directory.Delete(biTestDir, recursive: true); } catch (Exception) { /* temp cleanup - ignore if already removed */ }
    }
}
