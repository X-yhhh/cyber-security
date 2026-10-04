package com.xyh.cybersecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/** 启动网络威胁研判平台后端控制面。 */
@SpringBootApplication
@EnableScheduling
public class CyberSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(CyberSecurityApplication.class, args);
    }
}
