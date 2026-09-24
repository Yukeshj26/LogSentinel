package com.forensics.loganalyzer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/** LogSentinel � Real-Time Log Analysis & Threat Detection Platform. */
@SpringBootApplication
@EnableScheduling
public class LogAnalyzerApplication {
    public static void main(String[] args) {
        SpringApplication.run(LogAnalyzerApplication.class, args);
    }
}
