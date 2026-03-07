package com.bypassfuzzer.burp.smoke;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.lang.reflect.Array;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

final class MontoyaStubs {

    private MontoyaStubs() {
    }

    static HttpService httpService(String host, int port, boolean secure) {
        return (HttpService) Proxy.newProxyInstance(
            HttpService.class.getClassLoader(),
            new Class<?>[]{HttpService.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "host" -> host;
                case "port" -> port;
                case "secure" -> secure;
                case "ipAddress" -> host;
                case "toString" -> (secure ? "https" : "http") + "://" + host + ":" + port;
                case "hashCode" -> Objects.hash(host, port, secure);
                case "equals" -> proxy == args[0];
                default -> defaultValue(method.getReturnType());
            }
        );
    }

    static HttpRequest request(HttpService service, String rawRequest) {
        return request(parseRequest(service, rawRequest));
    }

    static HttpResponse response(byte[] rawResponseBytes) {
        return response(parseResponse(rawResponseBytes));
    }

    static HttpResponse syntheticResponse(int statusCode, String reasonPhrase, String body, List<HeaderState> headers) {
        String bodyText = body == null ? "" : body;
        List<HeaderState> allHeaders = new ArrayList<>(headers);
        boolean hasContentType = allHeaders.stream().anyMatch(header -> header.name().equalsIgnoreCase("Content-Type"));
        if (!hasContentType) {
            allHeaders.add(new HeaderState("Content-Type", "text/plain; charset=utf-8"));
        }
        boolean hasContentLength = allHeaders.stream().anyMatch(header -> header.name().equalsIgnoreCase("Content-Length"));
        if (!hasContentLength) {
            allHeaders.add(new HeaderState("Content-Length", Integer.toString(bodyText.getBytes(StandardCharsets.UTF_8).length)));
        }
        ResponseState state = new ResponseState("HTTP/1.1", (short) statusCode, reasonPhrase, allHeaders, bodyText);
        return response(state);
    }

    private static HttpRequest request(RequestState state) {
        return (HttpRequest) Proxy.newProxyInstance(
            HttpRequest.class.getClassLoader(),
            new Class<?>[]{HttpRequest.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "isInScope" -> false;
                case "httpService" -> state.service();
                case "url" -> buildUrl(state.service(), state.path());
                case "method" -> state.method();
                case "path" -> state.path();
                case "query" -> queryFromPath(state.path());
                case "pathWithoutQuery" -> pathWithoutQuery(state.path());
                case "fileExtension" -> fileExtension(state.path());
                case "hasHeader" -> hasHeader(state.headers(), args);
                case "headerValue" -> headerValue(state.headers(), (String) args[0]);
                case "headers" -> state.headers().stream().map(MontoyaStubs::header).toList();
                case "httpVersion" -> state.httpVersion();
                case "bodyOffset" -> rawRequest(state).indexOf("\r\n\r\n") + 4;
                case "body" -> byteArray(state.body().getBytes(StandardCharsets.UTF_8));
                case "bodyToString" -> state.body();
                case "markers" -> List.of();
                case "contains" -> containsRequest(state, args);
                case "toByteArray" -> byteArray(rawRequest(state).getBytes(StandardCharsets.UTF_8));
                case "toString" -> rawRequest(state);
                case "copyToTempFile" -> proxy;
                case "withService" -> request(state.withService((HttpService) args[0]));
                case "withPath" -> request(state.withPath((String) args[0]));
                case "withMethod" -> request(state.withMethod((String) args[0]));
                case "withBody" -> request(state.withBody(readBodyArg(args[0])));
                case "withAddedHeader" -> request(state.withAddedHeader(readHeader(args)));
                case "withUpdatedHeader" -> request(state.withUpdatedHeader(readHeader(args)));
                case "withRemovedHeader" -> request(state.withRemovedHeader(readHeaderName(args[0])));
                case "withHeader" -> request(state.withUpdatedHeader(readHeader(args)));
                case "withAddedHeaders" -> request(state.withAddedHeaders(readHeaders(args[0])));
                case "withUpdatedHeaders" -> request(state.withUpdatedHeaders(readHeaders(args[0])));
                case "withRemovedHeaders" -> request(state.withRemovedHeaders(readHeaders(args[0])));
                case "withDefaultHeaders", "withMarkers", "withAddedParameters", "withRemovedParameters",
                    "withUpdatedParameters", "withParameter", "withTransformationApplied" -> proxy;
                case "parameter", "parameterValue" -> null;
                case "parameters" -> List.of();
                case "hasParameters", "hasParameter" -> false;
                case "contentType" -> null;
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> defaultValue(method.getReturnType());
            }
        );
    }

    private static HttpResponse response(ResponseState state) {
        return (HttpResponse) Proxy.newProxyInstance(
            HttpResponse.class.getClassLoader(),
            new Class<?>[]{HttpResponse.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "statusCode" -> state.statusCode();
                case "reasonPhrase" -> state.reasonPhrase();
                case "cookies", "keywordCounts", "attributes", "markers" -> List.of();
                case "cookie", "cookieValue" -> null;
                case "hasCookie" -> false;
                case "mimeType", "statedMimeType", "inferredMimeType" -> null;
                case "hasHeader" -> hasHeader(state.headers(), args);
                case "header" -> header(state.headers().stream()
                    .filter(h -> h.name().equalsIgnoreCase((String) args[0]))
                    .findFirst()
                    .orElse(null));
                case "headerValue" -> headerValue(state.headers(), (String) args[0]);
                case "headers" -> state.headers().stream().map(MontoyaStubs::header).toList();
                case "httpVersion" -> state.httpVersion();
                case "bodyOffset" -> rawResponse(state).indexOf("\r\n\r\n") + 4;
                case "body" -> byteArray(state.body().getBytes(StandardCharsets.UTF_8));
                case "bodyToString" -> state.body();
                case "contains" -> containsResponse(state, args);
                case "toByteArray" -> byteArray(rawResponse(state).getBytes(StandardCharsets.UTF_8));
                case "toString" -> rawResponse(state);
                case "copyToTempFile", "withStatusCode", "withReasonPhrase", "withHttpVersion",
                    "withBody", "withAddedHeader", "withAddedHeaders", "withUpdatedHeader",
                    "withUpdatedHeaders", "withRemovedHeader", "withRemovedHeaders", "withMarkers" -> proxy;
                case "isStatusCodeClass" -> false;
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> defaultValue(method.getReturnType());
            }
        );
    }

    private static HttpHeader header(HeaderState headerState) {
        if (headerState == null) {
            return null;
        }
        return (HttpHeader) Proxy.newProxyInstance(
            HttpHeader.class.getClassLoader(),
            new Class<?>[]{HttpHeader.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "name" -> headerState.name();
                case "value" -> headerState.value();
                case "toString" -> headerState.name() + ": " + headerState.value();
                case "hashCode" -> Objects.hash(headerState.name(), headerState.value());
                case "equals" -> proxy == args[0];
                default -> defaultValue(method.getReturnType());
            }
        );
    }

    private static ByteArray byteArray(byte[] bytes) {
        byte[] copy = Arrays.copyOf(bytes, bytes.length);
        return (ByteArray) Proxy.newProxyInstance(
            ByteArray.class.getClassLoader(),
            new Class<?>[]{ByteArray.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "length" -> copy.length;
                case "getBytes" -> Arrays.copyOf(copy, copy.length);
                case "getByte" -> copy[(Integer) args[0]];
                case "toString" -> new String(copy, StandardCharsets.UTF_8);
                case "iterator" -> iterator(copy);
                case "copy", "copyToTempFile" -> byteArray(copy);
                case "subArray" -> subArray(copy, args);
                case "hashCode" -> Arrays.hashCode(copy);
                case "equals" -> proxy == args[0];
                default -> defaultValue(method.getReturnType());
            }
        );
    }

    private static Iterator<Byte> iterator(byte[] bytes) {
        List<Byte> byteList = new ArrayList<>(bytes.length);
        for (byte value : bytes) {
            byteList.add(value);
        }
        return byteList.iterator();
    }

    private static ByteArray subArray(byte[] bytes, Object[] args) {
        int from = (Integer) args[0];
        int to = (Integer) args[1];
        return byteArray(Arrays.copyOfRange(bytes, from, to));
    }

    private static RequestState parseRequest(HttpService service, String rawRequest) {
        String[] sections = rawRequest.split("\\r?\\n\\r?\\n", 2);
        String head = sections[0];
        String body = sections.length > 1 ? sections[1] : "";
        String[] lines = head.split("\\r?\\n");
        String[] requestLine = lines[0].split(" ", 3);
        List<HeaderState> headers = new ArrayList<>();
        for (int i = 1; i < lines.length; i++) {
            if (lines[i].isBlank() || !lines[i].contains(":")) {
                continue;
            }
            int colon = lines[i].indexOf(':');
            headers.add(new HeaderState(lines[i].substring(0, colon), lines[i].substring(colon + 1).trim()));
        }
        return new RequestState(service, requestLine[0], requestLine[1], requestLine[2], headers, body);
    }

    private static ResponseState parseResponse(byte[] rawResponseBytes) {
        String rawResponse = new String(rawResponseBytes, StandardCharsets.UTF_8);
        String[] sections = rawResponse.split("\\r?\\n\\r?\\n", 2);
        String head = sections[0];
        String body = sections.length > 1 ? sections[1] : "";
        String[] lines = head.split("\\r?\\n");
        String[] statusLine = lines[0].split(" ", 3);
        short statusCode = statusLine.length > 1 ? Short.parseShort(statusLine[1]) : 0;
        String reasonPhrase = statusLine.length > 2 ? statusLine[2] : "";
        List<HeaderState> headers = new ArrayList<>();
        for (int i = 1; i < lines.length; i++) {
            if (lines[i].isBlank() || !lines[i].contains(":")) {
                continue;
            }
            int colon = lines[i].indexOf(':');
            headers.add(new HeaderState(lines[i].substring(0, colon), lines[i].substring(colon + 1).trim()));
        }
        return new ResponseState(statusLine[0], statusCode, reasonPhrase, headers, body);
    }

    private static String rawRequest(RequestState state) {
        return state.method() + " " + state.path() + " " + state.httpVersion() + "\r\n"
            + renderHeaders(state.headers())
            + "\r\n"
            + state.body();
    }

    private static String rawResponse(ResponseState state) {
        return state.httpVersion() + " " + state.statusCode() + " " + state.reasonPhrase() + "\r\n"
            + renderHeaders(state.headers())
            + "\r\n"
            + state.body();
    }

    private static String renderHeaders(List<HeaderState> headers) {
        StringBuilder builder = new StringBuilder();
        for (HeaderState header : headers) {
            builder.append(header.name()).append(": ").append(header.value()).append("\r\n");
        }
        return builder.toString();
    }

    private static boolean hasHeader(List<HeaderState> headers, Object[] args) {
        if (args[0] instanceof String headerName) {
            if (args.length == 1) {
                return headers.stream().anyMatch(header -> header.name().equalsIgnoreCase(headerName));
            }
            if (args[1] instanceof String headerValue) {
                return headers.stream().anyMatch(header ->
                    header.name().equalsIgnoreCase(headerName) && header.value().equalsIgnoreCase(headerValue));
            }
        }
        if (args[0] instanceof HttpHeader header) {
            return headers.stream().anyMatch(existing ->
                existing.name().equalsIgnoreCase(header.name()) && existing.value().equals(header.value()));
        }
        return false;
    }

    private static String headerValue(List<HeaderState> headers, String headerName) {
        return headers.stream()
            .filter(header -> header.name().equalsIgnoreCase(headerName))
            .map(HeaderState::value)
            .findFirst()
            .orElse(null);
    }

    private static boolean containsRequest(RequestState state, Object[] args) {
        return containsText(rawRequest(state), args);
    }

    private static boolean containsResponse(ResponseState state, Object[] args) {
        return containsText(rawResponse(state), args);
    }

    private static boolean containsText(String text, Object[] args) {
        Object pattern = args[0];
        if (pattern instanceof String value) {
            return text.contains(value);
        }
        if (pattern instanceof Pattern regex) {
            return regex.matcher(text).find();
        }
        return false;
    }

    private static HeaderState readHeader(Object[] args) {
        if (args.length == 1 && args[0] instanceof HttpHeader header) {
            return new HeaderState(header.name(), header.value());
        }
        return new HeaderState((String) args[0], (String) args[1]);
    }

    private static String readHeaderName(Object arg) {
        return arg instanceof HttpHeader header ? header.name() : (String) arg;
    }

    private static String readBodyArg(Object arg) {
        if (arg instanceof ByteArray byteArray) {
            return byteArray.toString();
        }
        return (String) arg;
    }

    private static List<HeaderState> readHeaders(Object arg) {
        if (arg instanceof List<?> list) {
            return list.stream()
                .filter(HttpHeader.class::isInstance)
                .map(HttpHeader.class::cast)
                .map(header -> new HeaderState(header.name(), header.value()))
                .toList();
        }
        int length = Array.getLength(arg);
        List<HeaderState> headers = new ArrayList<>(length);
        for (int i = 0; i < length; i++) {
            HttpHeader header = (HttpHeader) Array.get(arg, i);
            headers.add(new HeaderState(header.name(), header.value()));
        }
        return headers;
    }

    private static String buildUrl(HttpService service, String path) {
        String scheme = service.secure() ? "https" : "http";
        return scheme + "://" + service.host() + ":" + service.port() + path;
    }

    private static String queryFromPath(String path) {
        int questionMark = path.indexOf('?');
        return questionMark == -1 ? "" : path.substring(questionMark + 1);
    }

    private static String pathWithoutQuery(String path) {
        int questionMark = path.indexOf('?');
        return questionMark == -1 ? path : path.substring(0, questionMark);
    }

    private static String fileExtension(String path) {
        String basePath = pathWithoutQuery(path);
        int slash = basePath.lastIndexOf('/');
        int dot = basePath.lastIndexOf('.');
        if (dot == -1 || dot < slash) {
            return "";
        }
        return basePath.substring(dot + 1);
    }

    private static Object defaultValue(Class<?> returnType) {
        if (returnType == boolean.class) {
            return false;
        }
        if (returnType == byte.class) {
            return (byte) 0;
        }
        if (returnType == short.class) {
            return (short) 0;
        }
        if (returnType == int.class) {
            return 0;
        }
        if (returnType == long.class) {
            return 0L;
        }
        return null;
    }

    private record HeaderState(String name, String value) {
    }

    private record RequestState(
        HttpService service,
        String method,
        String path,
        String httpVersion,
        List<HeaderState> headers,
        String body
    ) {
        private RequestState withService(HttpService newService) {
            return new RequestState(newService, method, path, httpVersion, headers, body);
        }

        private RequestState withPath(String newPath) {
            return new RequestState(service, method, newPath, httpVersion, headers, body);
        }

        private RequestState withMethod(String newMethod) {
            return new RequestState(service, newMethod, path, httpVersion, headers, body);
        }

        private RequestState withBody(String newBody) {
            return syncContentLength(new RequestState(service, method, path, httpVersion, headers, newBody == null ? "" : newBody));
        }

        private RequestState withAddedHeader(HeaderState newHeader) {
            List<HeaderState> updated = new ArrayList<>(headers);
            updated.add(newHeader);
            return new RequestState(service, method, path, httpVersion, updated, body);
        }

        private RequestState withUpdatedHeader(HeaderState newHeader) {
            List<HeaderState> updated = new ArrayList<>();
            boolean replaced = false;
            for (HeaderState header : headers) {
                if (header.name().equalsIgnoreCase(newHeader.name())) {
                    updated.add(newHeader);
                    replaced = true;
                } else {
                    updated.add(header);
                }
            }
            if (!replaced) {
                updated.add(newHeader);
            }
            return new RequestState(service, method, path, httpVersion, updated, body);
        }

        private RequestState withRemovedHeader(String headerName) {
            List<HeaderState> updated = headers.stream()
                .filter(header -> !header.name().equalsIgnoreCase(headerName))
                .toList();
            return new RequestState(service, method, path, httpVersion, updated, body);
        }

        private RequestState withAddedHeaders(List<HeaderState> newHeaders) {
            List<HeaderState> updated = new ArrayList<>(headers);
            updated.addAll(newHeaders);
            return new RequestState(service, method, path, httpVersion, updated, body);
        }

        private RequestState withUpdatedHeaders(List<HeaderState> newHeaders) {
            RequestState state = this;
            for (HeaderState header : newHeaders) {
                state = state.withUpdatedHeader(header);
            }
            return state;
        }

        private RequestState withRemovedHeaders(List<HeaderState> headersToRemove) {
            List<String> names = headersToRemove.stream().map(header -> header.name().toLowerCase(Locale.ROOT)).toList();
            List<HeaderState> updated = headers.stream()
                .filter(header -> !names.contains(header.name().toLowerCase(Locale.ROOT)))
                .toList();
            return new RequestState(service, method, path, httpVersion, updated, body);
        }

        private RequestState syncContentLength(RequestState state) {
            List<HeaderState> updated = state.headers.stream()
                .filter(header -> !header.name().equalsIgnoreCase("Content-Length"))
                .collect(java.util.stream.Collectors.toCollection(ArrayList::new));
            if (!state.body.isEmpty()) {
                updated.add(new HeaderState("Content-Length", Integer.toString(state.body.getBytes(StandardCharsets.UTF_8).length)));
            }
            return new RequestState(state.service, state.method, state.path, state.httpVersion, updated, state.body);
        }
    }

    private record ResponseState(
        String httpVersion,
        short statusCode,
        String reasonPhrase,
        List<HeaderState> headers,
        String body
    ) {
    }
}
