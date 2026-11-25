package io.github.realnribal.hsmkms.campaign;

import io.github.realnribal.hsmkms.tools.TnrReportGenerator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class ReportGeneratorTest {

    @Test
    @Requirement("REQ-RPT-001")
    @DisplayName("REQ-RPT-001 the HTML report flags a regression")
    void reportFlagsARegression() throws Exception {
        Path root = Files.createTempDirectory("tnr-report");
        Files.createDirectories(root.resolve("requirements"));
        Files.writeString(root.resolve("requirements/catalog.json"), """
                {"requirements":[
                  {"id":"REQ-KEY-001","level":"functional","layer":"junit","inScope":true,"title":"AES","statement":"AES"},
                  {"id":"REQ-KEY-002","level":"functional","layer":"junit","inScope":true,"title":"RSA","statement":"RSA"},
                  {"id":"REQ-OOS-001","level":"out-of-scope","layer":"none","inScope":false,"title":"Certified","statement":"out"}
                ]}
                """);
        Path traceDir = root.resolve("kms-api/target/tnr");
        Files.createDirectories(traceDir);
        Files.writeString(traceDir.resolve("trace.json"), """
                [
                  {"id":"REQ-KEY-001","className":"demo.Key","test":"aes","status":"PASS","durationMs":4,"message":""},
                  {"id":"REQ-KEY-002","className":"demo.Key","test":"rsa","status":"FAIL","durationMs":9,"message":"signature mismatch"}
                ]
                """);
        Path history = root.resolve("reports/history");
        Files.createDirectories(history);
        Files.writeString(history.resolve("20200101T000000000Z-prev.json"), """
                {"generatedAt":"2020-01-01T00:00:00Z","passRate":100.0,"requirements":[
                  {"id":"REQ-KEY-001","status":"PASS"},
                  {"id":"REQ-KEY-002","status":"PASS"}
                ]}
                """);

        int code = new TnrReportGenerator().generate(root);
        String html = Files.readString(root.resolve("site/index.html"));
        assertThat(code).isEqualTo(1);
        assertThat(html).contains("CAMPAIGN FAIL");
        assertThat(html).contains("Regressions");
        assertThat(html).contains("REQ-KEY-002");
        assertThat(html).contains("signature mismatch");
        assertThat(html).contains("OUT_OF_SCOPE");
    }
}
