package com.xyh.cybersecurity.web;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.file.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.*;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

/** 外部 dist 托管：页面导航回退首页；缺失资源及保留命名空间返回 404，绝不返回伪 API 成功。 */
@Controller
@Profile("deploy")
public class DeployWebController {
    private final Path root;
    public DeployWebController(@Value("${cyber.guard.deploy.web-root}") String root) {
        this.root = DeployWebConfiguration.verify(root);
    }
    @RequestMapping(value = {"/", "/{*path}"}, method = {RequestMethod.GET, RequestMethod.HEAD})
    public ResponseEntity<Resource> resource(HttpServletRequest request) throws IOException {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        if (DeployWebConfiguration.reserved(path) || path.contains("%") || path.contains("\\") || path.contains("..")) throw missing();
        Path file = root.resolve(path.substring(1)).normalize();
        if (!file.startsWith(root)) throw missing();
        boolean exists = Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS);
        if (!exists) {
            if (path.startsWith("/assets/") || path.substring(path.lastIndexOf('/') + 1).contains(".")) throw missing();
            file = root.resolve("index.html");
        }
        if (!file.toRealPath().startsWith(root.toRealPath()) || Files.isSymbolicLink(file)) throw missing();
        MediaType type = MediaTypeFactory.getMediaType(file.getFileName().toString()).orElse(MediaType.APPLICATION_OCTET_STREAM);
        String cache = file.equals(root.resolve("index.html")) ? "no-store" :
                path.matches("/assets/[^/]+-[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9]+") ? "public, max-age=31536000, immutable" : "no-cache";
        return ResponseEntity.ok().contentType(type).header(HttpHeaders.CACHE_CONTROL, cache)
                .body(request.getMethod().equals("HEAD") ? null : new FileSystemResource(file));
    }
    private static ResponseStatusException missing() { return new ResponseStatusException(HttpStatus.NOT_FOUND); }
}
