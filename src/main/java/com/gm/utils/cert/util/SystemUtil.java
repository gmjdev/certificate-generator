package com.gm.utils.cert.util;

import java.io.IOException;
import java.util.Optional;
import java.util.Scanner;

import org.apache.commons.lang3.StringUtils;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
@Slf4j
public class SystemUtil {
    public static String getHostname() {
        String os = System.getProperty("os.name").toLowerCase();
        String hostname = "localhost";
        if (os.contains("win")) {
            hostname = System.getenv("COMPUTERNAME");
            hostname = StringUtils.isBlank(hostname) ? execReadToString("hostname") : hostname;
        } else if (os.contains("nix") || os.contains("nux") || os.contains("mac os x")) {
            hostname = System.getenv("HOSTNAME");
            hostname = StringUtils.isBlank(hostname) ? execReadToString("hostname") : hostname;
            hostname = StringUtils.isBlank(hostname) ? execReadToString("cat /etc/hostname") : hostname;
        }
        return hostname.trim();
    }

    private static String execReadToString(String execCommand) {
        try (Scanner s = new Scanner(Runtime.getRuntime().exec(execCommand).getInputStream()).useDelimiter("\\A")) {
            return s.hasNext() ? s.next() : "";
        } catch (IOException e) {
            log.error("Failed to execute command: {}", execCommand, e);
        }
        return "localhost";
    }

    public static Optional<String> getDefaultJavaHome() {
        String javaHome = System.getenv("JAVA_HOME");
        if (StringUtils.isBlank(javaHome)) {
            javaHome = System.getenv("java.home");
        }
        return Optional.ofNullable(javaHome);
    }

    public static Optional<String> getEnvironmentValue(String variableName) {
        String javaHome = System.getenv(variableName);
        return Optional.ofNullable(javaHome);
    }
}
