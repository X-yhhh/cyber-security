package com.xyh.cybersecurity.web;

import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.*;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class DeployWebTest {
    @TempDir Path root;
    MockMvc mvc;
    @BeforeEach void setup() throws Exception {
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"));
        Files.writeString(root.resolve("index.html"), "<html>console</html>");
        Files.createDirectory(root.resolve("assets"));
        Files.writeString(root.resolve("assets/app-12345678.js"), "console.log(1)");
        try (var walk = Files.walk(root)) {
            for (Path p : (Iterable<Path>) walk::iterator) Files.setPosixFilePermissions(p,
                    PosixFilePermissions.fromString(Files.isDirectory(p) ? "rwx------" : "rw-------"));
        }
        mvc = MockMvcBuilders.standaloneSetup(new DeployWebController(root.toString()), new Api()).build();
    }
    @RestController static class Api { @GetMapping("/api/v2/probe") String probe() { return "api"; } }
    @Test void navigationAndCache() throws Exception {
        for (String url : new String[]{"/", "/login", "/console/detect/events/123", "/unknown-route"})
            mvc.perform(get(url)).andExpect(status().isOk()).andExpect(content().string("<html>console</html>"))
                    .andExpect(header().string("Cache-Control", "no-store"));
        mvc.perform(get("/assets/app-12345678.js")).andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "public, max-age=31536000, immutable"));
        mvc.perform(head("/console/workbench")).andExpect(status().isOk()).andExpect(content().string(""));
    }
    @Test void apiAndMissingAssetsNeverFallback() throws Exception {
        mvc.perform(get("/api/v2/probe")).andExpect(content().string("api"));
        for (String url : new String[]{"/api/v2/missing", "/api", "/actuator/missing", "/assets/missing.js", "/../secret"})
            mvc.perform(get(url)).andExpect(status().isNotFound());
    }
    @Test void unsafeRootsRefuseStartup() throws Exception {
        assertThatThrownBy(() -> DeployWebConfiguration.verify(null)).hasMessageContaining("WEB_ROOT_INVALID");
        assertThatThrownBy(() -> DeployWebConfiguration.verify("relative")).hasMessageContaining("WEB_ROOT_INVALID");
        Files.delete(root.resolve("index.html"));
        assertThatThrownBy(() -> DeployWebConfiguration.verify(root.toString())).hasMessageContaining("WEB_ROOT_INVALID");
    }
    @Test void broadPermissionsAndSymlinksRefused() throws Exception {
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwxr-xr-x"));
        assertThatThrownBy(() -> DeployWebConfiguration.verify(root.toString())).hasMessageContaining("WEB_ROOT_INVALID");
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"));
        Files.createSymbolicLink(root.resolve("link"), root.resolve("index.html"));
        assertThatThrownBy(() -> DeployWebConfiguration.verify(root.toString())).hasMessageContaining("WEB_ROOT_INVALID");
    }
}
