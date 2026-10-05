package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.nio.file.*;
import java.io.IOException;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 仅从管理员配置根目录读取有界制品；拒绝任意 URL、绝对路径、穿越及越界符号链接。 */
@Component
public class GuardArtifacts {
    private final Path root;
    public GuardArtifacts(@Value("${cyber.guard.artifact-root:}") String root){this.root=root.isBlank()?null:Path.of(root).toAbsolutePath();}
    public byte[] read(String ref,String expected,long max){
        try {require(root!=null,"ARTIFACT_ROOT_NOT_CONFIGURED");require(ref!=null&&ref.matches("[A-Za-z0-9][A-Za-z0-9._/-]{0,240}")&&!ref.contains(".."),"ARTIFACT_REFERENCE_INVALID");
            Path base=root.toRealPath(),p=base.resolve(ref).toRealPath();require(p.startsWith(base)&&Files.isRegularFile(p)&&Files.size(p)<=max,"ARTIFACT_REFERENCE_INVALID");
            byte[] bytes=Files.readAllBytes(p);require(bytes.length<=max,"ARTIFACT_TOO_LARGE");if(expected!=null)require(sha(bytes).equals(expected),"ARTIFACT_HASH_MISMATCH");return bytes;
        }catch(IOException e){throw error(422,"ARTIFACT_UNAVAILABLE");}
    }
    public JsonNode json(String ref,String expected){return parse(new String(read(ref,expected,1024*1024),java.nio.charset.StandardCharsets.UTF_8));}
    public static String sibling(String ref,String name){int i=ref.lastIndexOf('/');return (i<0?"":ref.substring(0,i+1))+name;}
}
