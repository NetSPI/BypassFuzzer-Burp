package com.bypassfuzzer.burp.core.payloads;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Generates malformed double-port Host values intended to expose parser
 * differences between front-end and back-end HTTP components.
 */
public final class HostPortBypassPayloadGenerator {

    private static final List<Integer> COMMON_FIRST_PORTS = List.of(80, 443, 8000, 8080, 8443);
    private static final List<String> TRAILING_PORTS = List.of("80", "443");
    private static final List<String> MALFORMED_PORTS = List.of("", "0", "65535", "abc");

    public List<HostPortPayload> generate(HttpRequest request, String targetUrl) {
        HttpService service = request == null ? null : request.httpService();
        Authority serviceAuthority = authorityFromService(service);
        if (serviceAuthority == null) {
            serviceAuthority = authorityFromUrl(targetUrl);
        }

        String originalHost = request == null ? null : trimToNull(request.headerValue("Host"));
        Authority originalAuthority = parseAuthority(originalHost);
        Authority mutationAuthority = originalAuthority != null ? originalAuthority : serviceAuthority;
        if (mutationAuthority == null) {
            return List.of();
        }

        String formattedHost = formatHost(mutationAuthority.host());
        Map<String, HostPortPayload> payloads = new LinkedHashMap<>();

        // Preserve the exact literal Host for the core append technique, even
        // when it is already malformed and cannot be parsed structurally.
        if (originalHost != null && (originalAuthority == null || originalAuthority.port() != null)) {
            for (String trailingPort : TRAILING_PORTS) {
                add(payloads, originalHost + ":" + trailingPort, "direct append");
            }
        }

        Set<Integer> firstPorts = new LinkedHashSet<>();
        if (originalAuthority != null && originalAuthority.port() != null) {
            firstPorts.add(originalAuthority.port());
        }
        if (serviceAuthority != null && serviceAuthority.port() != null) {
            firstPorts.add(serviceAuthority.port());
        }
        firstPorts.addAll(COMMON_FIRST_PORTS);

        for (int firstPort : firstPorts) {
            for (String trailingPort : TRAILING_PORTS) {
                add(payloads, formattedHost + ":" + firstPort + ":" + trailingPort, "numeric matrix");
            }
        }

        int anchorPort = anchorPort(originalAuthority, serviceAuthority, targetUrl);
        for (String malformedPort : MALFORMED_PORTS) {
            add(payloads, formattedHost + ":" + malformedPort + ":80", "malformed first port");
            add(payloads, formattedHost + ":" + anchorPort + ":" + malformedPort, "malformed trailing port");
        }

        return new ArrayList<>(payloads.values());
    }

    /**
     * Builds the two highest-value probes for broad sweep usage without adding
     * the full port and malformed-value matrix to every candidate.
     */
    public List<HostPortPayload> generateLightweight(HttpRequest request) {
        return generateLightweight(request, List.of());
    }

    /**
     * Builds lightweight probes. When {@code customPorts} contains real port
     * numbers (1-65535), each custom port generates three additional probes:
     * {@code host:customPort}, {@code host:customPort:80}, and
     * {@code host:customPort:443}. The standard two trailing-port probes are
     * always included. Entries with port 0 are treated as a no-op sentinel
     * (enabled but no custom ports).
     */
    public List<HostPortPayload> generateLightweight(HttpRequest request, List<Integer> customPorts) {
        if (request == null) {
            return List.of();
        }

        Authority serviceAuthority = authorityFromService(request.httpService());
        if (serviceAuthority == null) {
            serviceAuthority = authorityFromUrl(safeUrl(request));
        }

        String originalHost = trimToNull(request.headerValue("Host"));
        Authority originalAuthority = parseAuthority(originalHost);
        String baseAuthority;
        if (originalAuthority != null) {
            int firstPort = originalAuthority.port() != null
                ? originalAuthority.port()
                : fallbackPort(serviceAuthority);
            baseAuthority = formatHost(originalAuthority.host()) + ":" + firstPort;
        } else if (originalHost != null) {
            // Preserve malformed authorities literally for the append trick.
            baseAuthority = originalHost;
        } else if (serviceAuthority != null) {
            baseAuthority = formatHost(serviceAuthority.host()) + ":" + fallbackPort(serviceAuthority);
        } else {
            return List.of();
        }

        String formattedHost = null;
        if (originalAuthority != null) {
            formattedHost = formatHost(originalAuthority.host());
        } else if (serviceAuthority != null) {
            formattedHost = formatHost(serviceAuthority.host());
        }

        List<HostPortPayload> result = new ArrayList<>();

        // Custom port probes: host:customPort, host:customPort:80, host:customPort:443
        if (customPorts != null && formattedHost != null) {
            for (int customPort : customPorts) {
                if (customPort < 1 || customPort > 65535) {
                    continue;
                }
                result.add(new HostPortPayload(formattedHost + ":" + customPort, "custom port"));
                for (String trailingPort : TRAILING_PORTS) {
                    result.add(new HostPortPayload(
                        formattedHost + ":" + customPort + ":" + trailingPort, "custom port"));
                }
            }
        }

        // Standard lightweight probes: baseAuthority:80, baseAuthority:443
        for (String port : TRAILING_PORTS) {
            result.add(new HostPortPayload(baseAuthority + ":" + port, "lightweight sweep"));
        }

        return result;
    }

    private void add(Map<String, HostPortPayload> payloads, String value, String family) {
        payloads.putIfAbsent(value, new HostPortPayload(value, family));
    }

    private int anchorPort(Authority originalAuthority, Authority serviceAuthority, String targetUrl) {
        if (originalAuthority != null && originalAuthority.port() != null) {
            return originalAuthority.port();
        }
        if (serviceAuthority != null && serviceAuthority.port() != null) {
            return serviceAuthority.port();
        }
        Authority urlAuthority = authorityFromUrl(targetUrl);
        return urlAuthority != null && urlAuthority.port() != null ? urlAuthority.port() : 443;
    }

    private int fallbackPort(Authority authority) {
        return authority != null && authority.port() != null ? authority.port() : 443;
    }

    private String safeUrl(HttpRequest request) {
        try {
            return request.url();
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private Authority authorityFromService(HttpService service) {
        if (service == null || trimToNull(service.host()) == null) {
            return null;
        }
        Integer port = service.port() > 0 ? service.port() : (service.secure() ? 443 : 80);
        return new Authority(stripIpv6Brackets(service.host().trim()), port);
    }

    private Authority authorityFromUrl(String targetUrl) {
        try {
            URI uri = URI.create(targetUrl);
            String host = trimToNull(uri.getHost());
            if (host == null) {
                return null;
            }
            int port = uri.getPort() > 0 ? uri.getPort() : ("http".equalsIgnoreCase(uri.getScheme()) ? 80 : 443);
            return new Authority(stripIpv6Brackets(host), port);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private Authority parseAuthority(String authority) {
        if (authority == null || containsIllegalAuthorityCharacters(authority)) {
            return null;
        }

        if (authority.startsWith("[")) {
            int closingBracket = authority.indexOf(']');
            if (closingBracket <= 1) {
                return null;
            }
            String host = authority.substring(1, closingBracket);
            String suffix = authority.substring(closingBracket + 1);
            if (suffix.isEmpty()) {
                return new Authority(host, null);
            }
            if (!suffix.startsWith(":") || suffix.indexOf(':', 1) >= 0) {
                return null;
            }
            Integer port = parsePort(suffix.substring(1));
            return port == null ? null : new Authority(host, port);
        }

        int firstColon = authority.indexOf(':');
        if (firstColon < 0) {
            return new Authority(authority, null);
        }
        if (firstColon != authority.lastIndexOf(':')) {
            // An unbracketed IPv6 literal has no safely distinguishable port.
            return looksLikeIpv6(authority) ? new Authority(authority, null) : null;
        }

        String host = authority.substring(0, firstColon);
        Integer port = parsePort(authority.substring(firstColon + 1));
        return host.isEmpty() || port == null ? null : new Authority(host, port);
    }

    private Integer parsePort(String value) {
        try {
            if (value.isEmpty() || !value.chars().allMatch(Character::isDigit)) {
                return null;
            }
            int port = Integer.parseInt(value);
            return port >= 0 && port <= 65535 ? port : null;
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private boolean containsIllegalAuthorityCharacters(String authority) {
        return authority.isBlank() || authority.indexOf('/') >= 0 || authority.indexOf('\\') >= 0
            || authority.indexOf('@') >= 0 || authority.chars().anyMatch(Character::isWhitespace);
    }

    private boolean looksLikeIpv6(String authority) {
        if (!authority.matches("(?i)[0-9a-f:.]+")) {
            return false;
        }
        long colonCount = authority.chars().filter(character -> character == ':').count();
        return authority.contains("::") || colonCount >= 7;
    }

    private String formatHost(String host) {
        String unbracketed = stripIpv6Brackets(host);
        return unbracketed.indexOf(':') >= 0 ? "[" + unbracketed + "]" : unbracketed;
    }

    private String stripIpv6Brackets(String host) {
        if (host != null && host.length() > 1 && host.startsWith("[") && host.endsWith("]")) {
            return host.substring(1, host.length() - 1);
        }
        return host;
    }

    private String trimToNull(String value) {
        if (value == null || value.trim().isEmpty()) {
            return null;
        }
        return value.trim();
    }

    private record Authority(String host, Integer port) {
    }

    public record HostPortPayload(String value, String family) {
    }
}
