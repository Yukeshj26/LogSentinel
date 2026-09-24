package com.forensics.loganalyzer.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Exposes admin-privilege status and elevation actions.
 * Provides in-app permission checks, automated script launching,
 * and explorer reveal actions so the user can easily enable live
 * Windows Security log streaming.
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    /** Returns current admin status and diagnostic metadata. */
    @GetMapping("/status")
    public Map<String, Object> status() {
        Map<String, Object> result = new LinkedHashMap<>();
        boolean admin = isRunningAsAdmin();
        result.put("isAdmin", admin);
        result.put("isWindows", isWindows());
        result.put("os", System.getProperty("os.name", "unknown"));
        result.put("canElevate", isWindows() && !admin);
        result.put("jarPath", resolveJarPath());
        result.put("scriptPath", resolveScriptPath());
        return result;
    }

    /** Quick diagnostic endpoint to test direct wevtutil Security log query. */
    @GetMapping("/test-security-log")
    public Map<String, Object> testSecurityLog() {
        Map<String, Object> result = new LinkedHashMap<>();
        if (!isWindows()) {
            result.put("accessible", false);
            result.put("message", "Not running on Windows");
            return result;
        }
        try {
            Process p = new ProcessBuilder("wevtutil", "qe", "Security", "/q:*[System[(EventID=4624)]]", "/f:xml", "/c:1", "/rd:true")
                    .redirectErrorStream(true)
                    .start();
            boolean finished = p.waitFor(4, TimeUnit.SECONDS);
            if (!finished) {
                p.destroyForcibly();
                result.put("accessible", false);
                result.put("message", "Timed out testing wevtutil");
                return result;
            }
            int exitCode = p.exitValue();
            result.put("accessible", exitCode == 0);
            result.put("exitCode", exitCode);
            result.put("message", exitCode == 0 ? "Security log accessible" : "Access denied (requires Administrator)");
        } catch (Exception e) {
            result.put("accessible", false);
            result.put("message", e.getMessage());
        }
        return result;
    }

    /**
     * Opens Windows File Explorer with run-admin.bat highlighted.
     */
    @PostMapping("/open-folder")
    public ResponseEntity<Map<String, Object>> openFolder() {
        Map<String, Object> response = new LinkedHashMap<>();
        if (!isWindows()) {
            response.put("success", false);
            response.put("message", "Only supported on Windows.");
            return ResponseEntity.badRequest().body(response);
        }
        String scriptPath = resolveScriptPath();
        try {
            if (scriptPath != null && new File(scriptPath).exists()) {
                new ProcessBuilder("explorer.exe", "/select,\"" + scriptPath + "\"").start();
            } else {
                new ProcessBuilder("explorer.exe", Paths.get("").toAbsolutePath().toString()).start();
            }
            response.put("success", true);
            response.put("message", "Opened project folder in File Explorer.");
            return ResponseEntity.ok(response);
        } catch (Exception ex) {
            response.put("success", false);
            response.put("message", "Could not open explorer: " + ex.getMessage());
            return ResponseEntity.internalServerError().body(response);
        }
    }

    /**
     * Triggers elevation flow:
     * 1. Attempts to launch run-admin.bat via Shell.Application.
     * 2. Opens File Explorer highlighting run-admin.bat so the user can easily run or double click it.
     */
    @PostMapping("/elevate")
    public ResponseEntity<Map<String, Object>> elevate() {
        Map<String, Object> response = new LinkedHashMap<>();

        if (!isWindows()) {
            response.put("success", false);
            response.put("message", "Elevation is only supported on Windows.");
            return ResponseEntity.badRequest().body(response);
        }

        if (isRunningAsAdmin()) {
            response.put("success", false);
            response.put("message", "Application is already running with Administrator privileges.");
            return ResponseEntity.ok(response);
        }

        String scriptPath = resolveScriptPath();
        File runAdminBat = scriptPath != null ? new File(scriptPath) : null;
        String workDir = runAdminBat != null ? runAdminBat.getParentFile().getAbsolutePath() : Paths.get("").toAbsolutePath().toString();
        String safeWorkDir = workDir.replace("'", "''");

        // Open explorer with run-admin.bat highlighted
        try {
            if (runAdminBat != null && runAdminBat.exists()) {
                new ProcessBuilder("explorer.exe", "/select,\"" + runAdminBat.getAbsolutePath() + "\"").start();
            }
        } catch (Exception ignored) {}

        // Also attempt ShellExecute invocation
        try {
            String psCommand = String.format(
                    "(New-Object -ComObject Shell.Application).ShellExecute('cmd.exe', '/c run-admin.bat', '%s', 'runas', 1)",
                    safeWorkDir
            );
            new Thread(() -> {
                try {
                    new ProcessBuilder("powershell", "-NoProfile", "-Command", psCommand)
                            .inheritIO()
                            .start()
                            .waitFor(8, TimeUnit.SECONDS);
                } catch (Exception ignored) {}
            }).start();
        } catch (Exception ignored) {}

        response.put("success", true);
        response.put("scriptPath", scriptPath);
        response.put("powershellCmd", "Start-Process powershell -Verb RunAs -ArgumentList \"-Command cd '" + safeWorkDir + "'; .\\run-admin.bat\"");
        response.put("message", "Opened folder with run-admin.bat. Right-click it and choose 'Run as administrator', or approve the UAC prompt.");
        return ResponseEntity.ok(response);
    }

    /**
     * Checks if current process has Windows admin rights using 'net session'.
     * Falls back to testing wevtutil access directly.
     */
    public static boolean isRunningAsAdmin() {
        if (!isWindows()) return false;
        try {
            Process p = new ProcessBuilder("net", "session")
                    .redirectErrorStream(true)
                    .start();
            p.waitFor(3, TimeUnit.SECONDS);
            if (p.exitValue() == 0) {
                return true;
            }
        } catch (Exception ignored) {}

        // Fallback: test wevtutil on Security channel
        try {
            Process p = new ProcessBuilder("wevtutil", "qe", "Security", "/c:1")
                    .redirectErrorStream(true)
                    .start();
            p.waitFor(3, TimeUnit.SECONDS);
            return p.exitValue() == 0;
        } catch (Exception ignored) {}

        return false;
    }

    public static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    private static String resolveScriptPath() {
        File candidate = Paths.get("run-admin.bat").toAbsolutePath().toFile();
        if (candidate.exists()) return candidate.getAbsolutePath();

        String jarPath = resolveJarPath();
        if (jarPath != null) {
            File target = new File(jarPath).getParentFile();
            if (target != null && "target".equalsIgnoreCase(target.getName())) {
                File root = target.getParentFile();
                File bat = new File(root, "run-admin.bat");
                if (bat.exists()) return bat.getAbsolutePath();
            }
        }
        return null;
    }

    private static String resolveJarPath() {
        try {
            var loc = AdminController.class.getProtectionDomain().getCodeSource().getLocation();
            if (loc != null) {
                File codeFile = new File(loc.toURI());
                if (codeFile.isFile() && codeFile.getName().endsWith(".jar")) {
                    return codeFile.getAbsolutePath();
                }
            }
        } catch (Exception ignored) {}

        File candidate = Paths.get("target", "log-analyzer-1.0.0.jar").toAbsolutePath().toFile();
        if (candidate.exists()) return candidate.getAbsolutePath();

        File target = new File("target");
        if (target.isDirectory()) {
            File[] jars = target.listFiles(f -> f.getName().endsWith(".jar") && !f.getName().endsWith(".original"));
            if (jars != null && jars.length > 0) return jars[0].getAbsolutePath();
        }
        return null;
    }
}