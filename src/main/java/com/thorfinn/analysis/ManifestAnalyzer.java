package com.thorfinn.analysis;

import com.thorfinn.models.ManifestInfo;
import com.thorfinn.models.ManifestInfo.ExportedComponent;
import com.thorfinn.utils.PathUtils;
import lombok.extern.slf4j.Slf4j;
import org.w3c.dom.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

@Slf4j
public class ManifestAnalyzer {

    private static final String ANDROID_NS = "http://schemas.android.com/apk/res/android";

    public ManifestInfo analyze() {
        File manifestFile = findManifest();
        if (manifestFile == null) {
            log.error("[!] ManifestAnalyzer: AndroidManifest.xml not found");
            return ManifestInfo.builder()
                    .packageName("unknown")
                    .permissions(List.of())
                    .exportedActivities(List.of())
                    .exportedServices(List.of())
                    .exportedReceivers(List.of())
                    .exportedProviders(List.of())
                    .build();
        }

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            // Harden against XXE: disable DTDs and external entities entirely
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(manifestFile);
            doc.getDocumentElement().normalize();

            Element root = doc.getDocumentElement();

            String packageName = root.getAttribute("package");
            String versionName = root.getAttributeNS(ANDROID_NS, "versionName");
            String versionCode = root.getAttributeNS(ANDROID_NS, "versionCode");

            String minSdk = "";
            String targetSdk = "";
            NodeList usesSdkList = root.getElementsByTagName("uses-sdk");
            if (usesSdkList.getLength() > 0) {
                Element usesSdk = (Element) usesSdkList.item(0);
                minSdk = usesSdk.getAttributeNS(ANDROID_NS, "minSdkVersion");
                targetSdk = usesSdk.getAttributeNS(ANDROID_NS, "targetSdkVersion");
            }

            boolean debuggable = false;
            boolean allowBackup = false;
            boolean usesCleartextTraffic = false;
            NodeList appList = root.getElementsByTagName("application");
            if (appList.getLength() > 0) {
                Element app = (Element) appList.item(0);
                debuggable = "true".equals(app.getAttributeNS(ANDROID_NS, "debuggable"));
                allowBackup = "true".equals(app.getAttributeNS(ANDROID_NS, "allowBackup"));
                usesCleartextTraffic = "true".equals(app.getAttributeNS(ANDROID_NS, "usesCleartextTraffic"));
            }

            List<String> permissions = new ArrayList<>();
            NodeList permNodes = root.getElementsByTagName("uses-permission");
            for (int i = 0; i < permNodes.getLength(); i++) {
                Element perm = (Element) permNodes.item(i);
                String name = perm.getAttributeNS(ANDROID_NS, "name");
                if (!name.isEmpty()) permissions.add(name);
            }

            List<ExportedComponent> activities = parseExportedComponents(doc, "activity", packageName);
            List<ExportedComponent> services = parseExportedComponents(doc, "service", packageName);
            List<ExportedComponent> receivers = parseExportedComponents(doc, "receiver", packageName);
            List<ExportedComponent> providers = parseExportedComponents(doc, "provider", packageName);

            ManifestInfo info = ManifestInfo.builder()
                    .packageName(packageName)
                    .versionName(versionName)
                    .versionCode(versionCode)
                    .minSdkVersion(minSdk)
                    .targetSdkVersion(targetSdk)
                    .debuggable(debuggable)
                    .allowBackup(allowBackup)
                    .usesCleartextTraffic(usesCleartextTraffic)
                    .permissions(permissions)
                    .exportedActivities(activities)
                    .exportedServices(services)
                    .exportedReceivers(receivers)
                    .exportedProviders(providers)
                    .build();

            log.info("[*] ManifestAnalyzer: package={}, exported activities={}, services={}, receivers={}, providers={}",
                    packageName, activities.size(), services.size(), receivers.size(), providers.size());

            return info;

        } catch (Exception e) {
            log.error("[!] ManifestAnalyzer: Failed to parse manifest: {}", e.getMessage());
            return ManifestInfo.builder()
                    .packageName("parse-error")
                    .permissions(List.of())
                    .exportedActivities(List.of())
                    .exportedServices(List.of())
                    .exportedReceivers(List.of())
                    .exportedProviders(List.of())
                    .build();
        }
    }

    private List<ExportedComponent> parseExportedComponents(Document doc, String tagName, String packageName) {
        List<ExportedComponent> result = new ArrayList<>();
        NodeList nodes = doc.getElementsByTagName(tagName);

        for (int i = 0; i < nodes.getLength(); i++) {
            Element el = (Element) nodes.item(i);
            String name = el.getAttributeNS(ANDROID_NS, "name");
            String exported = el.getAttributeNS(ANDROID_NS, "exported");
            String permission = el.getAttributeNS(ANDROID_NS, "permission");

            List<String> intentFilters = new ArrayList<>();
            NodeList filterNodes = el.getElementsByTagName("intent-filter");
            for (int j = 0; j < filterNodes.getLength(); j++) {
                Element filter = (Element) filterNodes.item(j);
                StringBuilder filterDesc = new StringBuilder();

                NodeList actions = filter.getElementsByTagName("action");
                for (int k = 0; k < actions.getLength(); k++) {
                    String action = ((Element) actions.item(k)).getAttributeNS(ANDROID_NS, "name");
                    if (!action.isEmpty()) {
                        if (filterDesc.length() > 0) filterDesc.append(", ");
                        filterDesc.append("action=").append(action);
                    }
                }
                NodeList categories = filter.getElementsByTagName("category");
                for (int k = 0; k < categories.getLength(); k++) {
                    String cat = ((Element) categories.item(k)).getAttributeNS(ANDROID_NS, "name");
                    if (!cat.isEmpty()) {
                        if (filterDesc.length() > 0) filterDesc.append(", ");
                        filterDesc.append("category=").append(cat);
                    }
                }
                NodeList dataNodes = filter.getElementsByTagName("data");
                for (int k = 0; k < dataNodes.getLength(); k++) {
                    Element data = (Element) dataNodes.item(k);
                    String scheme = data.getAttributeNS(ANDROID_NS, "scheme");
                    String host = data.getAttributeNS(ANDROID_NS, "host");
                    String path = data.getAttributeNS(ANDROID_NS, "pathPrefix");
                    if (path.isEmpty()) path = data.getAttributeNS(ANDROID_NS, "path");
                    StringBuilder dataDesc = new StringBuilder();
                    if (!scheme.isEmpty()) dataDesc.append(scheme).append("://");
                    if (!host.isEmpty()) dataDesc.append(host);
                    if (!path.isEmpty()) dataDesc.append(path);
                    if (dataDesc.length() > 0) {
                        if (filterDesc.length() > 0) filterDesc.append(", ");
                        filterDesc.append("data=").append(dataDesc);
                    }
                }

                if (filterDesc.length() > 0) {
                    intentFilters.add(filterDesc.toString());
                }
            }

            boolean hasIntentFilter = !intentFilters.isEmpty();

            boolean isExported = "true".equals(exported) || (hasIntentFilter && !"false".equals(exported));

            if (isExported) {
                String fullName = name.startsWith(".") ? packageName + name : name;

                result.add(ExportedComponent.builder()
                        .name(fullName)
                        .permission(permission.isEmpty() ? null : permission)
                        .intentFilters(intentFilters)
                        .build());
            }
        }

        return result;
    }

    private File findManifest() {
        String decompiledPath = PathUtils.getDecompiledApkPath();
        String[] possiblePaths = {
                decompiledPath + "AndroidManifest.xml",
                decompiledPath + "resources/AndroidManifest.xml"
        };
        for (String path : possiblePaths) {
            File file = new File(path);
            if (file.exists()) {
                log.info("[*] ManifestAnalyzer: Found manifest at {}", path);
                return file;
            }
        }
        return null;
    }
}
