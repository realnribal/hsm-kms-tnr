package io.github.realnribal.hsmkms.tools;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * Builds the campaign HTML from the requirements catalog, the JUnit trace and the C JUnit XML.
 * Exit code is 0 only when every in-scope requirement passed.
 */
public final class TnrReportGenerator {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmssSSS'Z'")
            .withZone(ZoneOffset.UTC);

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("usage: TnrReportGenerator <repo-root>");
            System.exit(2);
        }
        int code = new TnrReportGenerator().generate(Path.of(args[0]));
        System.exit(code);
    }

    public int generate(Path root) throws Exception {
        List<Requirement> catalog = readCatalog(root.resolve("requirements/catalog.json"));
        Map<String, Observation> observations = new LinkedHashMap<>();
        readTrace(root.resolve("kms-api/target/tnr/trace.json"), observations);
        readJunit(root.resolve("native/build/c-junit.xml"), observations);
        Map<String, Metric> metrics = readMetrics(root.resolve("kms-api/target/tnr"));
        Previous previous = readPrevious(root.resolve("reports/history"));
        String log = readText(root.resolve("kms-api/target/tnr/kms-test.log"));
        String slots = readText(root.resolve(".softhsm/show-slots.txt"));
        String runtime = readText(root.resolve(".softhsm/runtime.txt"));

        List<Row> rows = new ArrayList<>();
        int passed = 0;
        int failed = 0;
        int notRun = 0;
        for (Requirement requirement : catalog) {
            Observation observation = observations.get(requirement.id());
            String status;
            if (!requirement.inScope()) {
                status = "OUT_OF_SCOPE";
            } else if (observation == null) {
                status = "NOT_RUN";
                notRun++;
            } else {
                status = observation.status();
                if ("PASS".equals(status)) {
                    passed++;
                } else {
                    failed++;
                }
            }
            Metric metric = metrics.get(requirement.id());
            rows.add(new Row(requirement, status, observation, metric));
        }
        int inScope = passed + failed + notRun;
        double passRate = inScope == 0 ? 0 : (passed * 100.0) / inScope;
        List<String> regressions = regressions(previous, rows);
        List<String> recovered = recovered(previous, rows);
        boolean verdict = failed == 0 && notRun == 0;
        String generatedAt = Instant.now().toString();
        String commit = gitShort(root);
        String runId = env("GITHUB_RUN_ID", "local");

        String html = render(new View(
                generatedAt, commit, runId, verdict, passed, failed, notRun, passRate,
                previous, regressions, recovered, rows, log, slots, runtime,
                System.getProperty("java.version"), System.getProperty("os.name")));

        Path site = root.resolve("site");
        Files.createDirectories(site);
        Files.writeString(site.resolve("index.html"), html);
        Files.createDirectories(root.resolve("reports"));
        Files.writeString(root.resolve("reports/tnr-report.html"), html);
        writeHistory(root.resolve("reports/history"), generatedAt, commit, runId, passed, failed, notRun, passRate, rows);

        System.out.println("TNR verdict: " + (verdict ? "PASS" : "FAIL"));
        System.out.printf("passed=%d failed=%d notRun=%d passRate=%.1f%n", passed, failed, notRun, passRate);
        if (!regressions.isEmpty()) {
            System.out.println("regressions: " + String.join(", ", regressions));
        }
        System.out.println("report: " + site.resolve("index.html"));
        return verdict ? 0 : 1;
    }

    private static List<Requirement> readCatalog(Path path) throws IOException {
        JsonNode root = JSON.readTree(Files.readString(path));
        List<Requirement> requirements = new ArrayList<>();
        for (JsonNode node : root.get("requirements")) {
            requirements.add(new Requirement(
                    node.get("id").asText(),
                    node.get("level").asText(),
                    node.get("layer").asText(),
                    node.get("inScope").asBoolean(),
                    node.get("title").asText(),
                    node.get("statement").asText()));
        }
        return requirements;
    }

    private static void readTrace(Path path, Map<String, Observation> observations) throws IOException {
        if (!Files.isRegularFile(path)) {
            return;
        }
        for (JsonNode node : JSON.readTree(Files.readString(path))) {
            String id = node.get("id").asText();
            Observation next = new Observation(
                    id,
                    node.path("className").asText(""),
                    node.path("test").asText(""),
                    node.path("status").asText("FAIL"),
                    node.path("durationMs").asLong(0),
                    node.path("message").asText(""));
            observations.merge(id, next, TnrReportGenerator::worse);
        }
    }

    private static void readJunit(Path path, Map<String, Observation> observations) throws Exception {
        if (!Files.isRegularFile(path)) {
            return;
        }
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        var document = factory.newDocumentBuilder().parse(path.toFile());
        var cases = document.getElementsByTagName("testcase");
        for (int i = 0; i < cases.getLength(); i++) {
            var node = cases.item(i);
            var attributes = node.getAttributes();
            String name = attributes.getNamedItem("name").getTextContent();
            String className = attributes.getNamedItem("classname") == null
                    ? "native.pkcs11"
                    : attributes.getNamedItem("classname").getTextContent();
            double seconds = attributes.getNamedItem("time") == null
                    ? 0
                    : Double.parseDouble(attributes.getNamedItem("time").getTextContent());
            String status = "PASS";
            String message = "";
            var children = node.getChildNodes();
            for (int c = 0; c < children.getLength(); c++) {
                String child = children.item(c).getNodeName();
                if ("failure".equals(child) || "error".equals(child)) {
                    status = "FAIL";
                    var messageAttr = children.item(c).getAttributes().getNamedItem("message");
                    message = messageAttr == null ? children.item(c).getTextContent() : messageAttr.getTextContent();
                }
            }
            Observation next = new Observation(name, className, name, status, Math.round(seconds * 1000), message);
            observations.merge(name, next, TnrReportGenerator::worse);
        }
    }

    private static Observation worse(Observation left, Observation right) {
        if ("FAIL".equals(left.status())) {
            return left;
        }
        return right;
    }

    private static Map<String, Metric> readMetrics(Path directory) throws IOException {
        Map<String, Metric> metrics = new LinkedHashMap<>();
        if (!Files.isDirectory(directory)) {
            return metrics;
        }
        try (Stream<Path> files = Files.list(directory)) {
            for (Path file : files.filter(path -> path.getFileName().toString().startsWith("metric-")).toList()) {
                JsonNode node = JSON.readTree(Files.readString(file));
                metrics.put(node.get("id").asText(), new Metric(
                        node.get("meanMs").asDouble(),
                        node.get("budgetMs").asLong(),
                        node.get("samples").asInt()));
            }
        }
        return metrics;
    }

    private static Previous readPrevious(Path directory) throws IOException {
        if (!Files.isDirectory(directory)) {
            return null;
        }
        List<Path> files;
        try (Stream<Path> listing = Files.list(directory)) {
            files = listing.filter(path -> path.getFileName().toString().endsWith(".json"))
                    .sorted(Comparator.comparing(path -> path.getFileName().toString()))
                    .toList();
        }
        if (files.isEmpty()) {
            return null;
        }
        JsonNode node = JSON.readTree(Files.readString(files.get(files.size() - 1)));
        Map<String, String> statuses = new LinkedHashMap<>();
        for (JsonNode requirement : node.withArray("requirements")) {
            statuses.put(requirement.get("id").asText(), requirement.get("status").asText());
        }
        return new Previous(
                node.path("generatedAt").asText(""),
                node.path("passRate").asDouble(0),
                statuses);
    }

    private static void writeHistory(Path directory, String generatedAt, String commit, String runId,
                                     int passed, int failed, int notRun, double passRate, List<Row> rows) throws IOException {
        Files.createDirectories(directory);
        ObjectNode root = JSON.createObjectNode();
        root.put("generatedAt", generatedAt);
        root.put("commit", commit);
        root.put("runId", runId);
        root.put("passed", passed);
        root.put("failed", failed);
        root.put("notRun", notRun);
        root.put("passRate", passRate);
        ArrayNode requirements = root.putArray("requirements");
        for (Row row : rows) {
            if (!row.requirement().inScope()) {
                continue;
            }
            ObjectNode item = requirements.addObject();
            item.put("id", row.requirement().id());
            item.put("status", row.status());
        }
        String name = STAMP.format(Instant.now()) + "-" + runId + ".json";
        JSON.writerWithDefaultPrettyPrinter().writeValue(directory.resolve(name).toFile(), root);
        JSON.writerWithDefaultPrettyPrinter().writeValue(directory.resolve("latest.json").toFile(), root);
    }

    private static List<String> regressions(Previous previous, List<Row> rows) {
        List<String> ids = new ArrayList<>();
        if (previous == null) {
            return ids;
        }
        for (Row row : rows) {
            if (!row.requirement().inScope()) {
                continue;
            }
            String before = previous.statuses().get(row.requirement().id());
            if ("PASS".equals(before) && !"PASS".equals(row.status())) {
                ids.add(row.requirement().id());
            }
        }
        return ids;
    }

    private static List<String> recovered(Previous previous, List<Row> rows) {
        List<String> ids = new ArrayList<>();
        if (previous == null) {
            return ids;
        }
        for (Row row : rows) {
            if (!row.requirement().inScope()) {
                continue;
            }
            String before = previous.statuses().get(row.requirement().id());
            if (before != null && !"PASS".equals(before) && "PASS".equals(row.status())) {
                ids.add(row.requirement().id());
            }
        }
        return ids;
    }

    private static String render(View view) {
        StringBuilder html = new StringBuilder();
        html.append("""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>HSM-KMS TNR campaign</title>
                <style>
                :root { color-scheme: light; }
                body { margin: 0; background: #f3efe6; color: #1a1814;
                  font-family: Palatino, "Iowan Old Style", Georgia, serif; }
                header { background: #243028; color: #f3efe6; padding: 28px 8vw 22px; }
                header p { margin: 6px 0 0; letter-spacing: 0.14em; text-transform: uppercase;
                  font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; color: #d7c7a1; }
                h1 { font-weight: 500; font-size: 34px; margin: 0; }
                main { padding: 28px 8vw 64px; }
                .stamp { display: inline-block; border: 2px solid currentColor; padding: 6px 12px;
                  letter-spacing: 0.16em; font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 13px; }
                .pass { color: #1f6b45; } .fail { color: #8e2f2f; } .muted { color: #6d655b; }
                .oos { color: #5c5348; }
                section { margin-top: 28px; }
                h2 { font-size: 18px; font-weight: 600; border-bottom: 1px solid #c8bfb0; padding-bottom: 6px; }
                dl { display: grid; grid-template-columns: 180px 1fr; gap: 4px 16px; }
                dt { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; color: #6d655b; }
                table { width: 100%; border-collapse: collapse; background: #fffdf8; }
                th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #e4dccf; vertical-align: top; }
                th { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 11px; letter-spacing: 0.08em;
                  text-transform: uppercase; color: #6d655b; }
                code, .mono { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 13px; }
                pre { white-space: pre-wrap; background: #fffdf8; border: 1px solid #e4dccf; padding: 12px;
                  font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; }
                .pill { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; }
                </style>
                </head>
                <body>
                <header>
                <p>IVVQ / non-regression</p>
                <h1>HSM-KMS TNR campaign</h1>
                </header>
                <main>
                """);
        html.append("<p class=\"stamp ").append(view.verdict() ? "pass" : "fail").append("\">")
                .append(view.verdict() ? "CAMPAIGN PASS" : "CAMPAIGN FAIL").append("</p>");
        html.append("<section><h2>How to read this page</h2><p>Start with the verdict and the regression list. ")
                .append("Each row is one requirement. A failure block quotes the assertion and the CKR name. ")
                .append("Match <span class=\"mono\">X-Trace-Id</span> from the API with <span class=\"mono\">trace=</span> in the log. ")
                .append("The trend compares this run with the previous archived campaign.</p></section>");

        html.append("<section><h2>Run</h2><dl>");
        def(html, "Generated", view.generatedAt());
        def(html, "Commit", view.commit());
        def(html, "Run", view.runId());
        def(html, "Java", view.javaVersion());
        def(html, "OS", view.osName());
        def(html, "Passed", Integer.toString(view.passed()));
        def(html, "Failed", Integer.toString(view.failed()));
        def(html, "Not run", Integer.toString(view.notRun()));
        def(html, "Pass rate", String.format(Locale.ROOT, "%.1f%%", view.passRate()));
        if (view.previous() == null) {
            def(html, "Trend", "No previous campaign archived yet. The next run will show the trend.");
        } else {
            double delta = view.passRate() - view.previous().passRate();
            def(html, "Trend", String.format(Locale.ROOT, "previous %.1f%% (%s), delta %+.1f pp",
                    view.previous().passRate(), view.previous().generatedAt(), delta));
        }
        html.append("</dl></section>");

        html.append("<section><h2>Environment</h2><pre>")
                .append(esc(trim(view.runtime(), 40)))
                .append("\n\n")
                .append(esc(trim(view.slots(), 60)))
                .append("</pre></section>");

        html.append("<section><h2>Regressions</h2>");
        if (view.regressions().isEmpty()) {
            html.append("<p>None. No in-scope requirement moved off PASS.</p>");
        } else {
            html.append("<ul>");
            for (String id : view.regressions()) {
                html.append("<li class=\"fail mono\">").append(esc(id)).append("</li>");
            }
            html.append("</ul>");
        }
        if (!view.recovered().isEmpty()) {
            html.append("<p>Recovered: ");
            html.append(esc(String.join(", ", view.recovered())));
            html.append("</p>");
        }
        html.append("</section>");

        html.append("<section><h2>Requirements</h2><table><thead><tr>")
                .append("<th>Id</th><th>Level</th><th>Status</th><th>Evidence</th><th>Title</th>")
                .append("</tr></thead><tbody>");
        for (Row row : view.rows()) {
            String css = switch (row.status()) {
                case "PASS" -> "pass";
                case "FAIL", "NOT_RUN" -> "fail";
                default -> "oos";
            };
            String evidence = "";
            if (row.observation() != null) {
                evidence = row.observation().className() + "#" + row.observation().test();
                if (row.observation().durationMs() > 0) {
                    evidence += " " + row.observation().durationMs() + " ms";
                }
            }
            if (row.metric() != null) {
                evidence += String.format(Locale.ROOT, " mean %.1f ms / budget %d ms",
                        row.metric().meanMs(), row.metric().budgetMs());
            }
            html.append("<tr><td class=\"mono\">").append(esc(row.requirement().id()))
                    .append("</td><td>").append(esc(row.requirement().level()))
                    .append("</td><td class=\"pill ").append(css).append("\">").append(esc(row.status()))
                    .append("</td><td class=\"mono\">").append(esc(evidence))
                    .append("</td><td>").append(esc(row.requirement().title()))
                    .append("</td></tr>");
        }
        html.append("</tbody></table></section>");

        html.append("<section><h2>Failure log</h2>");
        boolean anyFailure = false;
        for (Row row : view.rows()) {
            if (!"FAIL".equals(row.status()) && !"NOT_RUN".equals(row.status())) {
                continue;
            }
            anyFailure = true;
            String message = row.observation() == null ? "No observation was recorded for this requirement."
                    : row.observation().message();
            html.append("<h3 class=\"mono\">").append(esc(row.requirement().id())).append("</h3><pre>")
                    .append(esc(trimLine(message, 2000))).append("</pre>");
        }
        if (!anyFailure) {
            html.append("<p>No failures in this campaign.</p>");
        }
        html.append("</section>");

        html.append("<section><h2>Robustness evidence</h2><pre>");
        String evidence = filterLog(view.log());
        html.append(esc(evidence.isBlank() ? "No CKR or warning lines were captured." : evidence));
        html.append("</pre></section>");

        html.append("<section><h2>Limits</h2><p>SoftHSM2 is an open PKCS#11 token, not a certified HSM and not a ")
                .append("Thales ProtectServer. The bench does not claim vendor-specific mechanisms. ")
                .append("ECDSA is CKM_ECDSA over a SHA-256 digest because this SoftHSM build does not advertise ")
                .append("CKM_ECDSA_SHA256. Signatures are raw R||S. One session is shared and calls are serialized. ")
                .append("The lab API key is a campaign control, not mTLS.</p></section>");
        html.append("</main></body></html>\n");
        return html.toString();
    }

    private static void def(StringBuilder html, String name, String value) {
        html.append("<dt>").append(esc(name)).append("</dt><dd>").append(esc(value)).append("</dd>");
    }

    private static String filterLog(String log) {
        if (log == null || log.isBlank()) {
            return "";
        }
        String[] lines = log.split("\n");
        StringBuilder matched = new StringBuilder();
        int kept = 0;
        for (String line : lines) {
            if (line.contains("CKR_") || line.contains("level=WARN") || line.contains("level=ERROR")) {
                matched.append(trimLine(line, 400)).append('\n');
                kept++;
                if (kept == 40) {
                    break;
                }
            }
        }
        if (kept == 0) {
            int from = Math.max(0, lines.length - 20);
            for (int i = from; i < lines.length; i++) {
                matched.append(trimLine(lines[i], 400)).append('\n');
            }
        }
        return matched.toString();
    }

    private static String trim(String text, int lines) {
        if (text == null || text.isBlank()) {
            return "(not recorded)";
        }
        String[] parts = text.split("\n");
        StringBuilder out = new StringBuilder();
        int limit = Math.min(parts.length, lines);
        for (int i = 0; i < limit; i++) {
            out.append(parts[i]).append('\n');
        }
        return out.toString();
    }

    private static String trimLine(String text, int max) {
        if (text == null) {
            return "";
        }
        String flat = text.replace('\r', ' ');
        return flat.length() <= max ? flat : flat.substring(0, max) + "...";
    }

    private static String readText(Path path) {
        try {
            if (Files.isRegularFile(path)) {
                return Files.readString(path);
            }
        } catch (IOException ignored) {
            return "";
        }
        return "";
    }

    private static String esc(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static String env(String key, String fallback) {
        String value = System.getenv(key);
        return value == null || value.isBlank() ? fallback : value;
    }

    private static String gitShort(Path root) {
        String sha = System.getenv("GITHUB_SHA");
        if (sha != null && !sha.isBlank()) {
            return sha.length() > 12 ? sha.substring(0, 12) : sha;
        }
        try {
            Process process = new ProcessBuilder("git", "rev-parse", "--short", "HEAD")
                    .directory(root.toFile())
                    .redirectError(ProcessBuilder.Redirect.DISCARD)
                    .start();
            boolean finished = process.waitFor(5, TimeUnit.SECONDS);
            String output = new String(process.getInputStream().readAllBytes()).trim();
            if (finished && process.exitValue() == 0 && !output.isEmpty()) {
                return output;
            }
        } catch (Exception ignored) {
            return "unknown";
        }
        return "unknown";
    }

    private record Requirement(String id, String level, String layer, boolean inScope, String title, String statement) {
    }

    private record Observation(String id, String className, String test, String status, long durationMs, String message) {
    }

    private record Metric(double meanMs, long budgetMs, int samples) {
    }

    private record Previous(String generatedAt, double passRate, Map<String, String> statuses) {
    }

    private record Row(Requirement requirement, String status, Observation observation, Metric metric) {
    }

    private record View(
            String generatedAt,
            String commit,
            String runId,
            boolean verdict,
            int passed,
            int failed,
            int notRun,
            double passRate,
            Previous previous,
            List<String> regressions,
            List<String> recovered,
            List<Row> rows,
            String log,
            String slots,
            String runtime,
            String javaVersion,
            String osName) {
    }
}
