package io.scalecube.security.tokens.jwt;

import java.lang.reflect.Method;
import java.time.Duration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.test.StepVerifier;

public class BaseTest {

  protected static final Logger LOGGER = LoggerFactory.getLogger(BaseTest.class);

  public static final Duration TIMEOUT = Duration.ofSeconds(10);

  @BeforeAll
  public static void init() {
    StepVerifier.setDefaultTimeout(TIMEOUT);
  }

  @AfterAll
  public static void reset() {
    StepVerifier.resetDefaultTimeout();
  }

  @BeforeEach
  public final void baseSetUp(TestInfo testInfo) {
    LOGGER.info(
        "***** Test started  : "
            + testInfo.getTestClass().map(Class::getSimpleName).orElse("")
            + "."
            + testInfo.getTestMethod().map(Method::getName).orElse("")
            + " *****");
  }

  @AfterEach
  public final void baseTearDown(TestInfo testInfo) {
    LOGGER.info(
        "***** Test finished : "
            + testInfo.getTestClass().map(Class::getSimpleName).orElse("")
            + "."
            + testInfo.getTestMethod().map(Method::getName).orElse("")
            + " *****");
  }
}
