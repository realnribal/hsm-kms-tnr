package io.github.realnribal.hsmkms.campaign;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class TraceabilityTest {

    @Test
    @Requirement("REQ-TRC-001")
    @DisplayName("REQ-TRC-001 every in-scope Java requirement has one test")
    void everyJavaRequirementIsImplementedOnce() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode requirements = mapper.readTree(Files.readString(Path.of("..", "requirements", "catalog.json")))
                .get("requirements");
        String markdown = Files.readString(Path.of("..", "REQUIREMENTS.md"));
        Map<String, String> layers = new LinkedHashMap<>();
        Set<String> inScope = new LinkedHashSet<>();
        for (JsonNode node : requirements) {
            String id = node.get("id").asText();
            assertThat(markdown).contains(id);
            if (node.get("inScope").asBoolean()) {
                inScope.add(id);
                layers.put(id, node.get("layer").asText());
            }
        }

        Map<String, String> found = new LinkedHashMap<>();
        Path classes = Path.of("target", "test-classes", "io", "github", "realnribal", "hsmkms", "campaign");
        try (Stream<Path> walk = Files.walk(classes)) {
            for (Path classFile : walk.filter(path -> path.toString().endsWith(".class") && !path.toString().contains("$"))
                    .toList()) {
                String relative = classes.relativize(classFile).toString().replace('\\', '.').replace('/', '.');
                String className = "io.github.realnribal.hsmkms.campaign."
                        + relative.substring(0, relative.length() - ".class".length());
                Class<?> type = Class.forName(className);
                for (Method method : type.getDeclaredMethods()) {
                    if (!method.isAnnotationPresent(Test.class)) {
                        continue;
                    }
                    Requirement requirement = method.getAnnotation(Requirement.class);
                    assertThat(requirement).as(className + "#" + method.getName()).isNotNull();
                    assertThat(found).doesNotContainKey(requirement.value());
                    found.put(requirement.value(), method.getName());
                }
            }
        }

        for (String id : inScope) {
            if ("junit".equals(layers.get(id))) {
                assertThat(found).as(id).containsKey(id);
            }
        }
        for (String id : found.keySet()) {
            assertThat(inScope).contains(id);
            assertThat(layers.get(id)).isEqualTo("junit");
        }
    }
}
