package com.thorfinn.poc;

import com.phonepe.sentinelai.core.agent.Agent;
import com.phonepe.sentinelai.core.agent.AgentOutput;
import com.phonepe.sentinelai.core.agent.AgentRunContext;
import com.phonepe.sentinelai.core.agent.AgentSetup;
import com.phonepe.sentinelai.core.errorhandling.ErrorResponseHandler;
import com.phonepe.sentinelai.core.errors.ErrorType;
import com.phonepe.sentinelai.core.tools.Tool;
import com.phonepe.sentinelai.core.utils.ToolUtils;
import com.thorfinn.models.TaiEAgentModels;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
public class TaiEFlowAgent extends Agent<TaiEAgentModels.FlowRequest, TaiEAgentModels.FlowResponse, TaiEFlowAgent> {

    private static final String TOOL_READ_FILE_FULL = "read_file_full";
    private static final String TOOL_READ_MANIFEST = "read_manifest";
    private static final AtomicLong TOOL_CALL_SEQ = new AtomicLong(0);

    private static final String SYSTEM_PROMPT = """
            You are an expert Android security researcher analyzing taint flow findings from taie/Tai-e.
            Analyze one finding at a time.

            TOOLING AVAILABLE:
            - read_file_full(className, codeLabel)
            - read_manifest()
            Retrieval strategy:
            1) Fetch source/sink/intermediate class files with read_file_full.
            2) Fetch AndroidManifest.xml with read_manifest.
            3) Analyze this exact flow using fetched evidence only.
            Keep retrieval focused to avoid unnecessary token overhead.

            IMPORTANT RULES:
            - Analyze each finding INDIVIDUALLY. Base your verdict ONLY on the CURRENT code. Do NOT consider hypothetical fixes.
            - Only mark TRUE POSITIVE if THIS exact source-sink pair is exploitable as-is. A different exploitable path in the same code does not make the given flow a TP.
            - Lack of sanitization in the current code = TRUE POSITIVE regardless of whether it could be added later.

            VULNERABILITY REFERENCE KNOWLEDGE:

            1. WebView Vulnerability: Attacker-controlled data (Intent extras, deep links) flows into WebView.loadUrl(), loadData(), or evaluateJavascript() without validation.

            2. Third-Party Package Context Code Execution: App scans installed packages (getInstalledPackages/getInstalledApplications), matches by weak criteria (package name prefix/suffix/contains), calls createPackageContext(pkg, CONTEXT_INCLUDE_CODE | CONTEXT_IGNORE_SECURITY), then loads and invokes classes via reflection with no signature verification (checkSignatures()).

            3. Intent Redirection: Exported component extracts a nested Intent and passes it to a component launcher, allowing attacker to reach non-exported components.
               EXTRACTION PATTERNS: getParcelableExtra(), getExtras().get/getParcelable(), Intent.parseUri(stringExtra), getParcelableArrayExtra()[0], getParcelableArrayListExtra().get(0), Fragment.getArguments().getParcelable()
               SINKS: startActivity(), startActivityForResult(), startService(), sendBroadcast(), sendOrderedBroadcast(), setResult(RESULT_OK, intent), startActivities()
               NOTE — setResult: Attacker can set FLAG_GRANT_READ/WRITE_URI_PERMISSION on an internal provider URI; when victim activity returns via setResult(), attacker gains URI grant access to the victim's protected content providers.
               TRUE POSITIVE if: source exported AND nested Intent extracted via above patterns AND passed to sink without component validation.
               FALSE POSITIVE if: source not exported OR component/package validated before use OR app builds a fresh Intent(this, Target.class) using only data from extras.

            4. Implicit Intent Interception: Intent created via new Intent("ACTION") or new Intent("ACTION", uri) (no explicit component) reaches startActivity/startActivityForResult/sendBroadcast/startService/bindService/PendingIntent. Attacker app with matching intent-filter intercepts it.
               TRUE POSITIVE if: Intent stays implicit to the sink (no setComponent/setClass/setClassName/setPackage between constructor and sink) AND sent where external apps can receive it AND carries sensitive data or performs a sensitive operation.
               FALSE POSITIVE if: explicit component set before sink OR LocalBroadcastManager used OR signature-level permission on sendBroadcast OR FLAG_IMMUTABLE on PendingIntent OR safe system action with no sensitive extras.

            5. Path Traversal in Content Providers: Exported ContentProvider uses getLastPathSegment()/getPathSegments()/getPath() (which auto-URL-decode: ..%2F→../) in file path construction without sanitizing "..".
               TRUE POSITIVE if: ContentProvider exported AND path segment used directly in file construction AND no ".." check or canonicalPath validation.
               FALSE POSITIVE if: not exported OR canonicalPath checked against base dir OR ".." rejected OR path comes from DB lookup (not URI).

            6. Content Provider Proxy / URI Forwarding: Exported component forwards attacker-controlled URI to ContentResolver.query/insert/update/delete/openFile/openInputStream/openOutputStream.
               PATTERNS: Uri.parse(uri.getQueryParameter("uri")) → query(); getIntent().getStringExtra("target") → openInputStream(Uri.parse(target))
               TRUE POSITIVE if: source exported AND attacker URI forwarded to ContentResolver AND no authority/scheme validation.
               FALSE POSITIVE if: not exported OR URI authority/scheme validated against allowlist OR URI is hardcoded.
               IMPORTANT: If URI reaches a write-capable sink (openOutputStream, openFileDescriptor "w/rw/wt") and data is written, classify as Arbitrary File Write.

            7. Arbitrary File Write: Exported component accepts attacker-controlled Uri (via Intent extra, Bundle.getParcelable(), Intent.getData()) and opens it for WRITING using the app's own identity/permissions.
               WRITE-CAPABLE SINKS: openOutputStream(uri), openOutputStream(uri, mode), openFileDescriptor(uri, "w"/"rw"/"wt"), openAssetFileDescriptor(uri, "w").
               TRUE POSITIVE if: source exported AND attacker controls Uri target AND write-capable sink used AND no Uri allowlist/permission check.
               FALSE POSITIVE if: not exported OR Uri app-created OR read-only sink OR strict Uri allowlist enforced OR no privilege boundary bypass.

            9. Changing Device Settings: Exported component receives attacker-controlled Intent data and invokes privileged device APIs without caller validation, using the victim app's own permissions.
               PRIVILEGED SINKS: NotificationManager (cancelAll, cancel, setInterruptionFilter), TelephonyManager (resetAllCarrierActions, setDataEnabled, setDataRoamingEnabled), WifiManager (setWifiEnabled, disconnect, removeNetwork), AudioManager (setRingerMode, setMicrophoneMute, setStreamVolume), Settings.Global/System/Secure.put*(), PowerManager (reboot, goToSleep), DevicePolicyManager (lockNow, wipeData, setCameraDisabled), ConnectivityManager.setAirplaneMode(), AlarmManager (setTime, setTimeZone), BluetoothAdapter (enable, disable), KeyguardManager.disableKeyguard()
               KEY DISTINCTION: Attacker controls WHETHER/HOW the operation executes — they trigger the component and the app invokes the privileged API with ITS OWN permissions.
               TRUE POSITIVE if: source exported (no permission restriction) AND tainted data drives a privileged API AND app holds required permission AND no checkCallingPermission/checkCallingUid/enforceCallingPermission guard.
               FALSE POSITIVE if: not exported OR requires signature permission OR guarded by caller identity check OR app lacks the required permission OR state is app-internal only OR values are hardcoded.

            8. PendingIntent Redirection: App creates a PendingIntent wrapping an implicit/empty Intent with FLAG_MUTABLE (or pre-SDK31 default mutable), exposes it to an attacker who calls .send(ctx, 0, fillInIntent) supplying the missing component — borrowing victim app's UID and permissions.
               SOURCE: PendingIntent.getActivity/getBroadcast/getService/getForegroundService() returns tainted PendingIntent.
               EXPOSURE SINKS: putExtra("key", pi) → sendBroadcast/startActivity/startService/setResult; NotificationCompat/Notification.Builder setContentIntent/setDeleteIntent/setFullScreenIntent; RemoteViews.setOnClickPendingIntent.
               VULNERABLE (all three required): (1) Wrapped Intent is implicit — no setComponent/setClass/setClassName/setPackage/new Intent(ctx,Class.class); (2) FLAG_MUTABLE used OR no flag with targetSdkVersion < 31; (3) PendingIntent reaches attacker via an exposure sink.
               FALSE POSITIVE if: explicit component set OR FLAG_IMMUTABLE used OR PendingIntent never leaves app process OR setPackage() restricts recipient.
               NOTE: If targetSdkVersion >= 31 and no FLAG_MUTABLE, system throws exception — code likely sets a flag, verify which one.

            YOUR JOB:
            1. Is this flow a TRUE POSITIVE or FALSE POSITIVE?
            2. If TRUE POSITIVE, generate a concrete POC.

            POC PATTERNS:
            1. WebView Vulnerability: Single adb command opening attacker URL with all required parameters.
            2. Third-Party Package Context Code Execution: Describe the attack steps.
            3. Intent Redirection: Single adb command targeting a non-exported component (identify from manifest). No generic examples.
            4. Implicit Intent Interception: Describe the attack and provide sample attacker AndroidManifest.xml intent-filter.
            5. Path Traversal: adb shell "content read --uri content://authority/../../files/profileInstalled" — always use this exact path, never URL-encode.
            6. Content Provider Proxy: Match to how URI enters the app:
               a) Via ContentProvider query param: adb shell "content query --uri content://com.victim.proxy/path?uri=content://com.victim.private/secrets"
               b) Via Activity deep link (getData().getQueryParameter()): adb shell "am start -a android.intent.action.VIEW -d 'https://host/path?target=content://com.victim.private/secrets' com.victim"
               c) Via Activity string extra: adb shell "am start -n com.victim/.Activity --es key 'content://com.victim.private/secrets'"
               d) Via Activity data URI: adb shell "am start -n com.victim/.Activity -d 'content://com.victim.private/secrets'"
               Identify a non-exported provider from the manifest as the target. No generic example URIs.
            7. Arbitrary File Write: Match to how Uri enters:
               a) Intent extra: adb shell "am start -n com.victim/.Activity --eu output 'file:///sdcard/Download/thorfinn_poc_target.jpg'"
               b) Intent data: adb shell "am start -n com.victim/.Activity -d 'file:///sdcard/Download/thorfinn_poc_target.jpg'"
               c) Action-based: adb shell "am start -a <action> -n com.victim/.Activity --eu output 'file:///sdcard/Download/thorfinn_poc_target.jpg'"
               Use actual component name and extra key from code.
            8. Changing Device Settings:
               a) BroadcastReceiver: adb shell "am broadcast -a <action> -n com.victim/.Receiver [extras]"
               b) Activity/Service: adb shell "am start -n com.victim/.Activity [extras]"
               Use -n for explicit component targeting (required on Android 8+). Pick the action triggering the highest-impact sink. Use actual extra key names from code.
            9. PendingIntent Redirection: Cannot exploit via adb — requires an attacker app.
               Start with: NO_ADB_COMMAND
               Provide: (a) how attacker receives PendingIntent (BroadcastReceiver/NotificationListenerService/onActivityResult); (b) full attacker Java code with pi.send(ctx, 0, fillInIntent) where fillInIntent.setClassName() targets a non-exported victim component (from manifest); (c) attacker AndroidManifest.xml snippet; (d) impact description.

            CRITICAL POC FORMATTING RULES:
            - ALL adb commands MUST be on a SINGLE LINE.
            - ALL adb commands MUST wrap the shell portion in double quotes: adb shell "am start ..."
            - NEVER use backslash line continuations (\\) in adb commands.

            Return output only in this exact format:
            === VERDICT ===
            TRUE_POSITIVE or FALSE_POSITIVE

            === VULNERABILITY CLASS ===
            (write N/A if FALSE_POSITIVE)

            === ANALYSIS ===
            (detailed reasoning for this specific flow only)

            === POC ===
            (single-line adb command if applicable, else NO_ADB_COMMAND with reason and exploit code)
            """;

    public TaiEFlowAgent(AgentSetup setup, String decompiledRootPath) {
        super(TaiEAgentModels.FlowResponse.class,
                SYSTEM_PROMPT,
                setup,
                List.of(),
                ToolUtils.readTools(new LookupTools(decompiledRootPath)),
                null,
                null,
                new TaiEErrorHandler(),
                null
        );
        log.info("[TaiEAgent] Initialized with tools: {}", tools().keySet());
    }

    @Override
    public String name() {
        return "taie-flow-agent";
    }

    @SuppressWarnings("unchecked")
    private static final class TaiEErrorHandler implements ErrorResponseHandler<TaiEAgentModels.FlowRequest> {
        @Override
        public <U> AgentOutput<U> handle(AgentRunContext<TaiEAgentModels.FlowRequest> context, AgentOutput<U> output) {
            ErrorType errorType = output.getError() != null
                    ? output.getError().getErrorType()
                    : ErrorType.UNKNOWN;
            String errorMsg = output.getError() != null
                    ? output.getError().getMessage()
                    : "unknown";
            log.error("[TaiEAgent] Agent error: type={} message={} usage={}",
                    errorType, errorMsg, output.getUsage());
            TaiEAgentModels.FlowResponse fallback = new TaiEAgentModels.FlowResponse(
                    "FALSE_POSITIVE",
                    "N/A",
                    "Agent error (" + errorType + "): " + errorMsg,
                    "NO_ADB_COMMAND"
            );
            return (AgentOutput<U>) AgentOutput.success(
                    fallback,
                    output.getNewMessages(),
                    output.getAllMessages(),
                    output.getUsage()
            );
        }
    }

    public static final class LookupTools {
        private final TaiECodeLookupService lookupService;
        private final String decompiledRootPath;

        public LookupTools(String decompiledRootPath) {
            this.decompiledRootPath = decompiledRootPath;
            this.lookupService = new TaiECodeLookupService(decompiledRootPath);
            log.info("[TaiEAgent][tools] LookupTools ready for root: {}", decompiledRootPath);
        }

        @Tool(name = "read_file_full",
              value = "Read full class file content by class name and code label (JAVA/SMALI). Includes exact then fuzzy lookup.")
        public String readFileFull(String className, String codeLabel) {
            long callId = TOOL_CALL_SEQ.incrementAndGet();
            long startNs = System.nanoTime();
            log.info("[TaiEAgent][tool-call:{}][{}] START className={} codeLabel={}",
                    callId, TOOL_READ_FILE_FULL, className, codeLabel);
            if (className == null || className.isBlank()) {
                log.warn("[TaiEAgent][tool-call:{}][{}] BLANK_CLASS_NAME", callId, TOOL_READ_FILE_FULL);
                return "File not found for: " + className;
            }
            try {
                String label = codeLabel == null ? "" : codeLabel.trim();
                boolean useSmali = "SMALI".equalsIgnoreCase(label);
                String content = useSmali
                        ? lookupService.readSmaliClassWithFuzzy(className.trim())
                        : lookupService.readJavaClassWithFuzzy(className.trim());
                boolean found = useSmali
                        ? !content.startsWith("Smali file not found for:")
                        : !content.startsWith("Java file not found for:");
                long durationMs = (System.nanoTime() - startNs) / 1_000_000;
                log.info("[TaiEAgent][tool-call:{}][{}] END status={} bytes={} durationMs={}",
                        callId, TOOL_READ_FILE_FULL, found ? "FOUND" : "NOT_FOUND", content.length(), durationMs);
                return content;
            } catch (Exception e) {
                long durationMs = (System.nanoTime() - startNs) / 1_000_000;
                log.error("[TaiEAgent][tool-call:{}][{}] ERROR durationMs={} message={}",
                        callId, TOOL_READ_FILE_FULL, durationMs, e.getMessage());
                return "File not found for: " + className;
            }
        }

        @Tool(name = "read_manifest",
              value = "Read AndroidManifest.xml from decompiled output using apktool/jadx fallback locations.")
        public String readManifest() {
            long callId = TOOL_CALL_SEQ.incrementAndGet();
            long startNs = System.nanoTime();
            log.info("[TaiEAgent][tool-call:{}][{}] START", callId, TOOL_READ_MANIFEST);
            try {
                Path root = Path.of(decompiledRootPath);
                Path[] possiblePaths = {
                        root.resolve("AndroidManifest.xml"),
                        root.resolve("resources").resolve("AndroidManifest.xml")
                };

                for (Path manifestPath : possiblePaths) {
                    File file = manifestPath.toFile();
                    if (file.exists()) {
                        String manifest = Files.readString(manifestPath);
                        long durationMs = (System.nanoTime() - startNs) / 1_000_000;
                        log.info("[TaiEAgent][tool-call:{}][{}] END foundAt={} bytes={} durationMs={}",
                                callId, TOOL_READ_MANIFEST, manifestPath, manifest.length(), durationMs);
                        return manifest;
                    }
                }

                long durationMs = (System.nanoTime() - startNs) / 1_000_000;
                log.warn("[TaiEAgent][tool-call:{}][{}] NOT_FOUND durationMs={}",
                        callId, TOOL_READ_MANIFEST, durationMs);
                return "AndroidManifest.xml not found";
            } catch (Exception e) {
                long durationMs = (System.nanoTime() - startNs) / 1_000_000;
                log.error("[TaiEAgent][tool-call:{}][{}] ERROR durationMs={} message={}",
                        callId, TOOL_READ_MANIFEST, durationMs, e.getMessage());
                return "AndroidManifest.xml not found";
            }
        }
    }
}
