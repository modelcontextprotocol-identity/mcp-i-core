/**
 * Logger Unit Tests
 *
 * Tests transport-aware logging behavior:
 * - Level filtering
 * - Transport mode (stdio vs SSE/HTTP)
 * - Console method mapping
 */

import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import {
  createDefaultConsoleLogger,
  logger,
  type Logger,
  type Level,
} from "../logger.js";

describe("Logger - Level Filtering", () => {
  let testLogger: Logger;
  let consoleDebug: ReturnType<typeof vi.spyOn>;
  let consoleInfo: ReturnType<typeof vi.spyOn>;
  let consoleWarn: ReturnType<typeof vi.spyOn>;
  let consoleError: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    testLogger = createDefaultConsoleLogger();
    consoleDebug = vi.spyOn(console, "debug").mockImplementation(() => {});
    consoleInfo = vi.spyOn(console, "info").mockImplementation(() => {});
    consoleWarn = vi.spyOn(console, "warn").mockImplementation(() => {});
    consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should log all levels when level is 'debug'", () => {
    testLogger.configure({ level: "debug" });
    testLogger.debug("debug message");
    testLogger.info("info message");
    testLogger.warn("warn message");
    testLogger.error("error message");

    expect(consoleDebug).toHaveBeenCalledWith("debug message");
    expect(consoleInfo).toHaveBeenCalledWith("info message");
    expect(consoleWarn).toHaveBeenCalledWith("warn message");
    expect(consoleError).toHaveBeenCalledWith("error message");
  });

  it("should filter out debug when level is 'info'", () => {
    testLogger.configure({ level: "info" });
    testLogger.debug("debug message");
    testLogger.info("info message");
    testLogger.warn("warn message");
    testLogger.error("error message");

    expect(consoleDebug).not.toHaveBeenCalled();
    expect(consoleInfo).toHaveBeenCalledWith("info message");
    expect(consoleWarn).toHaveBeenCalledWith("warn message");
    expect(consoleError).toHaveBeenCalledWith("error message");
  });

  it("should filter out debug and info when level is 'warn'", () => {
    testLogger.configure({ level: "warn" });
    testLogger.debug("debug message");
    testLogger.info("info message");
    testLogger.warn("warn message");
    testLogger.error("error message");

    expect(consoleDebug).not.toHaveBeenCalled();
    expect(consoleInfo).not.toHaveBeenCalled();
    expect(consoleWarn).toHaveBeenCalledWith("warn message");
    expect(consoleError).toHaveBeenCalledWith("error message");
  });

  it("should only log error when level is 'error'", () => {
    testLogger.configure({ level: "error" });
    testLogger.debug("debug message");
    testLogger.info("info message");
    testLogger.warn("warn message");
    testLogger.error("error message");

    expect(consoleDebug).not.toHaveBeenCalled();
    expect(consoleInfo).not.toHaveBeenCalled();
    expect(consoleWarn).not.toHaveBeenCalled();
    expect(consoleError).toHaveBeenCalledWith("error message");
  });
});

describe("Logger - Transport Mode (SSE/HTTP)", () => {
  let testLogger: Logger;
  let consoleDebug: ReturnType<typeof vi.spyOn>;
  let consoleInfo: ReturnType<typeof vi.spyOn>;
  let consoleWarn: ReturnType<typeof vi.spyOn>;
  let consoleError: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    testLogger = createDefaultConsoleLogger();
    consoleDebug = vi.spyOn(console, "debug").mockImplementation(() => {});
    consoleInfo = vi.spyOn(console, "info").mockImplementation(() => {});
    consoleWarn = vi.spyOn(console, "warn").mockImplementation(() => {});
    consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should map levels to correct console methods for SSE transport", () => {
    testLogger.configure({ level: "debug", transport: "sse" });
    testLogger.debug("debug message");
    testLogger.info("info message");
    testLogger.warn("warn message");
    testLogger.error("error message");

    expect(consoleDebug).toHaveBeenCalledWith("debug message");
    expect(consoleInfo).toHaveBeenCalledWith("info message");
    expect(consoleWarn).toHaveBeenCalledWith("warn message");
    expect(consoleError).toHaveBeenCalledWith("error message");
  });

  it("should map levels to correct console methods for HTTP transport", () => {
    testLogger.configure({ level: "debug", transport: "http" });
    testLogger.debug("debug message");
    testLogger.info("info message");
    testLogger.warn("warn message");
    testLogger.error("error message");

    expect(consoleDebug).toHaveBeenCalledWith("debug message");
    expect(consoleInfo).toHaveBeenCalledWith("info message");
    expect(consoleWarn).toHaveBeenCalledWith("warn message");
    expect(consoleError).toHaveBeenCalledWith("error message");
  });
});

describe("Logger - Transport Mode (stdio)", () => {
  let testLogger: Logger;
  let consoleError: ReturnType<typeof vi.spyOn>;
  let consoleInfo: ReturnType<typeof vi.spyOn>;
  let consoleWarn: ReturnType<typeof vi.spyOn>;
  let consoleDebug: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    testLogger = createDefaultConsoleLogger();
    consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    consoleInfo = vi.spyOn(console, "info").mockImplementation(() => {});
    consoleWarn = vi.spyOn(console, "warn").mockImplementation(() => {});
    consoleDebug = vi.spyOn(console, "debug").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should route all levels to console.error for stdio transport", () => {
    testLogger.configure({ level: "debug", transport: "stdio" });
    testLogger.debug("debug message");
    testLogger.info("info message");
    testLogger.warn("warn message");
    testLogger.error("error message");

    // All should go to console.error (stderr)
    expect(consoleError).toHaveBeenCalledTimes(4);
    expect(consoleError).toHaveBeenCalledWith("debug message");
    expect(consoleError).toHaveBeenCalledWith("info message");
    expect(consoleError).toHaveBeenCalledWith("warn message");
    expect(consoleError).toHaveBeenCalledWith("error message");

    // Other console methods should not be called
    expect(consoleDebug).not.toHaveBeenCalled();
    expect(consoleInfo).not.toHaveBeenCalled();
    expect(consoleWarn).not.toHaveBeenCalled();
  });

  it("should route all levels to console.error when forceStderr is true", () => {
    testLogger.configure({ level: "debug", forceStderr: true });
    testLogger.debug("debug message");
    testLogger.info("info message");
    testLogger.warn("warn message");
    testLogger.error("error message");

    // All should go to console.error (stderr)
    expect(consoleError).toHaveBeenCalledTimes(4);
    expect(consoleError).toHaveBeenCalledWith("debug message");
    expect(consoleError).toHaveBeenCalledWith("info message");
    expect(consoleError).toHaveBeenCalledWith("warn message");
    expect(consoleError).toHaveBeenCalledWith("error message");

    // Other console methods should not be called
    expect(consoleDebug).not.toHaveBeenCalled();
    expect(consoleInfo).not.toHaveBeenCalled();
    expect(consoleWarn).not.toHaveBeenCalled();
  });

  it("should disable forceStderr when forceStderr is explicitly false", () => {
    testLogger.configure({ level: "debug", transport: "stdio" });
    testLogger.configure({ forceStderr: false });
    testLogger.debug("debug message");
    testLogger.info("info message");
    testLogger.warn("warn message");
    testLogger.error("error message");

    // Should use normal console method mapping
    expect(consoleDebug).toHaveBeenCalledWith("debug message");
    expect(consoleInfo).toHaveBeenCalledWith("info message");
    expect(consoleWarn).toHaveBeenCalledWith("warn message");
    expect(consoleError).toHaveBeenCalledWith("error message");
  });

  it("should reset forceStderr when switching from stdio to sse transport", () => {
    // First configure with stdio (should set forceStderr = true)
    testLogger.configure({ level: "debug", transport: "stdio" });
    testLogger.info("via stdio");
    expect(consoleError).toHaveBeenCalledWith("via stdio");

    // Clear mocks
    consoleError.mockClear();
    consoleInfo.mockClear();

    // Now switch to sse transport (should reset forceStderr = false)
    testLogger.configure({ transport: "sse" });
    testLogger.info("via sse");

    // Should use console.info, not console.error
    expect(consoleInfo).toHaveBeenCalledWith("via sse");
    expect(consoleError).not.toHaveBeenCalled();
  });

  it("should reset forceStderr when switching from stdio to http transport", () => {
    // First configure with stdio (should set forceStderr = true)
    testLogger.configure({ level: "debug", transport: "stdio" });
    testLogger.warn("via stdio");
    expect(consoleError).toHaveBeenCalledWith("via stdio");

    // Clear mocks
    consoleError.mockClear();
    consoleWarn.mockClear();

    // Now switch to http transport (should reset forceStderr = false)
    testLogger.configure({ transport: "http" });
    testLogger.warn("via http");

    // Should use console.warn, not console.error
    expect(consoleWarn).toHaveBeenCalledWith("via http");
    expect(consoleError).not.toHaveBeenCalled();
  });

  it("should respect explicit forceStderr:true even when transport is sse", () => {
    // Configure with sse but force stderr
    testLogger.configure({ level: "debug", transport: "sse", forceStderr: true });
    testLogger.info("forced to stderr");

    // Should use console.error because forceStderr is explicit
    expect(consoleError).toHaveBeenCalledWith("forced to stderr");
    expect(consoleInfo).not.toHaveBeenCalled();
  });
});

describe("Logger - Console Method Fallbacks", () => {
  let testLogger: Logger;
  let consoleLog: ReturnType<typeof vi.spyOn>;
  let consoleError: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    testLogger = createDefaultConsoleLogger();
    consoleLog = vi.spyOn(console, "log").mockImplementation(() => {});
    consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should fallback to console.log when console.debug is unavailable", () => {
    // Mock console.debug as undefined
    const originalDebug = console.debug;
    (console as any).debug = undefined;

    testLogger.configure({ level: "debug" });
    testLogger.debug("debug message");

    expect(consoleLog).toHaveBeenCalledWith("debug message");

    // Restore
    console.debug = originalDebug;
  });

  it("should fallback to console.log when console.info is unavailable", () => {
    // Mock console.info as undefined
    const originalInfo = console.info;
    (console as any).info = undefined;

    testLogger.configure({ level: "info" });
    testLogger.info("info message");

    expect(consoleLog).toHaveBeenCalledWith("info message");

    // Restore
    console.info = originalInfo;
  });

  it("should fallback to console.error when console.warn is unavailable", () => {
    // Mock console.warn as undefined
    const originalWarn = console.warn;
    (console as any).warn = undefined;

    testLogger.configure({ level: "warn" });
    testLogger.warn("warn message");

    expect(consoleError).toHaveBeenCalledWith("warn message");

    // Restore
    console.warn = originalWarn;
  });
});

describe("Logger - Singleton Instance", () => {
  it("should export a singleton logger instance", () => {
    expect(logger).toBeDefined();
    expect(typeof logger.debug).toBe("function");
    expect(typeof logger.info).toBe("function");
    expect(typeof logger.warn).toBe("function");
    expect(typeof logger.error).toBe("function");
    expect(typeof logger.configure).toBe("function");
  });

  it("should allow configuring the singleton logger", () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    const consoleInfo = vi.spyOn(console, "info").mockImplementation(() => {});

    logger.configure({ level: "info" });
    logger.debug("should not log");
    logger.info("should log");

    expect(consoleError).not.toHaveBeenCalled();
    expect(consoleInfo).toHaveBeenCalledWith("should log");

    vi.restoreAllMocks();
  });
});

describe("Logger - Multiple Arguments", () => {
  let testLogger: Logger;
  let consoleInfo: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    testLogger = createDefaultConsoleLogger();
    consoleInfo = vi.spyOn(console, "info").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should pass all arguments to console method", () => {
    testLogger.configure({ level: "debug" });
    testLogger.info("message", { key: "value" }, 123, true);

    expect(consoleInfo).toHaveBeenCalledWith(
      "message",
      { key: "value" },
      123,
      true
    );
  });
});
