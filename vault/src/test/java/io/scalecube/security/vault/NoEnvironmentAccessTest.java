package io.scalecube.security.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Build gate: production code of this module must not read process environment or system properties
 * behind the caller's back. All configuration is injected by the caller.
 */
class NoEnvironmentAccessTest {

  private static final Path MAIN_SOURCES = Paths.get("src", "main", "java");

  private static final Pattern FORBIDDEN =
      Pattern.compile("System\\.getenv|System\\.getProperty|(?<!No)EnvironmentLoader\\b");

  @Test
  void mainSourcesDoNotAccessEnvironment() throws IOException {
    final List<String> violations = new ArrayList<>();

    try (Stream<Path> files = Files.walk(MAIN_SOURCES)) {
      files
          .filter(path -> path.toString().endsWith(".java"))
          .forEach(
              path -> {
                try {
                  final List<String> lines = Files.readAllLines(path);
                  for (int i = 0; i < lines.size(); i++) {
                    if (FORBIDDEN.matcher(lines.get(i)).find()) {
                      violations.add(path + ":" + (i + 1) + ": " + lines.get(i).trim());
                    }
                  }
                } catch (IOException e) {
                  throw new IllegalStateException(e);
                }
              });
    }

    assertEquals(
        List.of(),
        violations,
        "Environment access in main sources (inject configuration instead): " + violations);
  }
}
