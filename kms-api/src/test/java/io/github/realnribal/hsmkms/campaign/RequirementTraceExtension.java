package io.github.realnribal.hsmkms.campaign;

import org.junit.jupiter.api.extension.BeforeTestExecutionCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestWatcher;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Writes {@code target/tnr/trace.json} so the HTML report can join each test to a requirement id.
 */
public final class RequirementTraceExtension implements BeforeTestExecutionCallback, TestWatcher {

    private static final Path PATH = Path.of("target", "tnr", "trace.json");
    private static final List<String> ROWS = new ArrayList<>();
    private static final ExtensionContext.Namespace NAMESPACE =
            ExtensionContext.Namespace.create(RequirementTraceExtension.class);

    static {
        try {
            Files.createDirectories(PATH.getParent());
        } catch (IOException ex) {
            throw new ExceptionInInitializerError(ex);
        }
    }

    @Override
    public void beforeTestExecution(ExtensionContext context) {
        context.getStore(NAMESPACE).put("start", System.nanoTime());
    }

    @Override
    public void testSuccessful(ExtensionContext context) {
        record(context, "PASS", "");
    }

    @Override
    public void testFailed(ExtensionContext context, Throwable cause) {
        record(context, "FAIL", cause == null ? "" : String.valueOf(cause.getMessage()));
    }

    @Override
    public void testAborted(ExtensionContext context, Throwable cause) {
        record(context, "FAIL", cause == null ? "aborted" : String.valueOf(cause.getMessage()));
    }

    private void record(ExtensionContext context, String status, String message) {
        Requirement requirement = context.getRequiredTestMethod().getAnnotation(Requirement.class);
        if (requirement == null) {
            return;
        }
        Long start = context.getStore(NAMESPACE).get("start", Long.class);
        long duration = start == null ? 0 : (System.nanoTime() - start) / 1_000_000L;
        String row = "{\"id\":\"" + json(requirement.value())
                + "\",\"className\":\"" + json(context.getRequiredTestClass().getName())
                + "\",\"test\":\"" + json(context.getRequiredTestMethod().getName())
                + "\",\"status\":\"" + status
                + "\",\"durationMs\":" + duration
                + ",\"message\":\"" + json(truncate(message)) + "\"}";
        synchronized (ROWS) {
            ROWS.add(row);
            persist();
        }
    }

    private static void persist() {
        StringBuilder json = new StringBuilder("[\n");
        for (int i = 0; i < ROWS.size(); i++) {
            if (i > 0) {
                json.append(",\n");
            }
            json.append(ROWS.get(i));
        }
        json.append("\n]\n");
        try {
            Files.createDirectories(PATH.getParent());
            Files.writeString(PATH, json.toString());
        } catch (IOException ex) {
            throw new IllegalStateException("cannot write " + PATH, ex);
        }
    }

    private static String truncate(String message) {
        if (message == null) {
            return "";
        }
        return message.length() <= 1500 ? message : message.substring(0, 1500);
    }

    private static String json(String value) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '\\' -> out.append("\\\\");
                case '"' -> out.append("\\\"");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (ch < 0x20) {
                        out.append(' ');
                    } else {
                        out.append(ch);
                    }
                }
            }
        }
        return out.toString();
    }
}
